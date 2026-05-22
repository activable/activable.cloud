package activable_ffi

// #include <activable_ffi.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"runtime/cgo"
	"unsafe"
)

// This is needed, because as of go 1.24
// type RustBuffer C.RustBuffer cannot have methods,
// RustBuffer is treated as non-local type
type GoRustBuffer struct {
	inner C.RustBuffer
}

type RustBufferI interface {
	AsReader() *bytes.Reader
	Free()
	ToGoBytes() []byte
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

// C.RustBuffer fields exposed as an interface so they can be accessed in different Go packages.
// See https://github.com/golang/go/issues/13467
type ExternalCRustBuffer interface {
	Data() unsafe.Pointer
	Len() uint64
	Capacity() uint64
}

func RustBufferFromC(b C.RustBuffer) ExternalCRustBuffer {
	return GoRustBuffer{
		inner: b,
	}
}

func CFromRustBuffer(b ExternalCRustBuffer) C.RustBuffer {
	return C.RustBuffer{
		capacity: C.uint64_t(b.Capacity()),
		len:      C.uint64_t(b.Len()),
		data:     (*C.uchar)(b.Data()),
	}
}

func RustBufferFromExternal(b ExternalCRustBuffer) GoRustBuffer {
	return GoRustBuffer{
		inner: C.RustBuffer{
			capacity: C.uint64_t(b.Capacity()),
			len:      C.uint64_t(b.Len()),
			data:     (*C.uchar)(b.Data()),
		},
	}
}

func (cb GoRustBuffer) Capacity() uint64 {
	return uint64(cb.inner.capacity)
}

func (cb GoRustBuffer) Len() uint64 {
	return uint64(cb.inner.len)
}

func (cb GoRustBuffer) Data() unsafe.Pointer {
	return unsafe.Pointer(cb.inner.data)
}

func (cb GoRustBuffer) AsReader() *bytes.Reader {
	b := unsafe.Slice((*byte)(cb.inner.data), C.uint64_t(cb.inner.len))
	return bytes.NewReader(b)
}

func (cb GoRustBuffer) Free() {
	rustCall(func(status *C.RustCallStatus) bool {
		C.ffi_activable_ffi_rustbuffer_free(cb.inner, status)
		return false
	})
}

func (cb GoRustBuffer) ToGoBytes() []byte {
	return C.GoBytes(unsafe.Pointer(cb.inner.data), C.int(cb.inner.len))
}

func stringToRustBuffer(str string) C.RustBuffer {
	return bytesToRustBuffer([]byte(str))
}

func bytesToRustBuffer(b []byte) C.RustBuffer {
	if len(b) == 0 {
		return C.RustBuffer{}
	}
	// We can pass the pointer along here, as it is pinned
	// for the duration of this call
	foreign := C.ForeignBytes{
		len:  C.int(len(b)),
		data: (*C.uchar)(unsafe.Pointer(&b[0])),
	}

	return rustCall(func(status *C.RustCallStatus) C.RustBuffer {
		return C.ffi_activable_ffi_rustbuffer_from_bytes(foreign, status)
	})
}

type BufLifter[GoType any] interface {
	Lift(value RustBufferI) GoType
}

type BufLowerer[GoType any] interface {
	Lower(value GoType) C.RustBuffer
}

type BufReader[GoType any] interface {
	Read(reader io.Reader) GoType
}

type BufWriter[GoType any] interface {
	Write(writer io.Writer, value GoType)
}

func LowerIntoRustBuffer[GoType any](bufWriter BufWriter[GoType], value GoType) C.RustBuffer {
	// This might be not the most efficient way but it does not require knowing allocation size
	// beforehand
	var buffer bytes.Buffer
	bufWriter.Write(&buffer, value)

	bytes, err := io.ReadAll(&buffer)
	if err != nil {
		panic(fmt.Errorf("reading written data: %w", err))
	}
	return bytesToRustBuffer(bytes)
}

func LiftFromRustBuffer[GoType any](bufReader BufReader[GoType], rbuf RustBufferI) GoType {
	defer rbuf.Free()
	reader := rbuf.AsReader()
	item := bufReader.Read(reader)
	if reader.Len() > 0 {
		// TODO: Remove this
		leftover, _ := io.ReadAll(reader)
		panic(fmt.Errorf("Junk remaining in buffer after lifting: %s", string(leftover)))
	}
	return item
}

func rustCallWithError[E any, U any](converter BufReader[E], callback func(*C.RustCallStatus) U) (U, E) {
	var status C.RustCallStatus
	returnValue := callback(&status)
	err := checkCallStatus(converter, status)
	return returnValue, err
}

func checkCallStatus[E any](converter BufReader[E], status C.RustCallStatus) E {
	switch status.code {
	case 0:
		var zero E
		return zero
	case 1:
		return LiftFromRustBuffer(converter, GoRustBuffer{inner: status.errorBuf})
	case 2:
		// when the rust code sees a panic, it tries to construct a rustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{inner: status.errorBuf})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		panic(fmt.Errorf("unknown status code: %d", status.code))
	}
}

func checkCallStatusUnknown(status C.RustCallStatus) error {
	switch status.code {
	case 0:
		return nil
	case 1:
		panic(fmt.Errorf("function not returning an error returned an error"))
	case 2:
		// when the rust code sees a panic, it tries to construct a C.RustBuffer
		// with the message.  but if that code panics, then it just sends back
		// an empty buffer.
		if status.errorBuf.len > 0 {
			panic(fmt.Errorf("%s", FfiConverterStringINSTANCE.Lift(GoRustBuffer{
				inner: status.errorBuf,
			})))
		} else {
			panic(fmt.Errorf("Rust panicked while handling Rust panic"))
		}
	default:
		return fmt.Errorf("unknown status code: %d", status.code)
	}
}

func rustCall[U any](callback func(*C.RustCallStatus) U) U {
	returnValue, err := rustCallWithError[error](nil, callback)
	if err != nil {
		panic(err)
	}
	return returnValue
}

type NativeError interface {
	AsError() error
}

func writeInt8(writer io.Writer, value int8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint8(writer io.Writer, value uint8) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt16(writer io.Writer, value int16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint16(writer io.Writer, value uint16) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt32(writer io.Writer, value int32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint32(writer io.Writer, value uint32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeInt64(writer io.Writer, value int64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeUint64(writer io.Writer, value uint64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat32(writer io.Writer, value float32) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func writeFloat64(writer io.Writer, value float64) {
	if err := binary.Write(writer, binary.BigEndian, value); err != nil {
		panic(err)
	}
}

func readInt8(reader io.Reader) int8 {
	var result int8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint8(reader io.Reader) uint8 {
	var result uint8
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt16(reader io.Reader) int16 {
	var result int16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint16(reader io.Reader) uint16 {
	var result uint16
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt32(reader io.Reader) int32 {
	var result int32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint32(reader io.Reader) uint32 {
	var result uint32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readInt64(reader io.Reader) int64 {
	var result int64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readUint64(reader io.Reader) uint64 {
	var result uint64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat32(reader io.Reader) float32 {
	var result float32
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func readFloat64(reader io.Reader) float64 {
	var result float64
	if err := binary.Read(reader, binary.BigEndian, &result); err != nil {
		panic(err)
	}
	return result
}

func init() {

	uniffiCheckChecksums()
}

func uniffiCheckChecksums() {
	// Get the bindings contract version from our ComponentInterface
	bindingsContractVersion := 30
	// Get the scaffolding contract version by calling the into the dylib
	scaffoldingContractVersion := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint32_t {
		return C.ffi_activable_ffi_uniffi_contract_version()
	})
	if bindingsContractVersion != int(scaffoldingContractVersion) {
		// If this happens try cleaning and rebuilding your project
		panic("activable_ffi: UniFFI contract version mismatch")
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_version()
		})
		if checksum != 5495 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_version: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_add_edge()
		})
		if checksum != 5712 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_add_edge: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_add_edges_batch()
		})
		if checksum != 49681 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_add_edges_batch: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_add_node()
		})
		if checksum != 33669 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_add_node: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_add_nodes_batch()
		})
		if checksum != 47769 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_add_nodes_batch: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_flush()
		})
		if checksum != 56883 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_flush: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_graph_initialize()
		})
		if checksum != 31868 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_graph_initialize: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_health_check()
		})
		if checksum != 59483 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_health_check: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_query_blast_radius()
		})
		if checksum != 46749 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_query_blast_radius: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_query_find_node()
		})
		if checksum != 41599 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_query_find_node: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_query_path_finder()
		})
		if checksum != 1027 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_query_path_finder: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_query_subgraph()
		})
		if checksum != 56879 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_query_subgraph: UniFFI API checksum mismatch")
		}
	}
	{
		checksum := rustCall(func(_uniffiStatus *C.RustCallStatus) C.uint16_t {
			return C.uniffi_activable_ffi_checksum_func_query_walk_edges()
		})
		if checksum != 63804 {
			// If this happens try cleaning and rebuilding your project
			panic("activable_ffi: uniffi_activable_ffi_checksum_func_query_walk_edges: UniFFI API checksum mismatch")
		}
	}
}

type FfiConverterUint16 struct{}

var FfiConverterUint16INSTANCE = FfiConverterUint16{}

func (FfiConverterUint16) Lower(value uint16) C.uint16_t {
	return C.uint16_t(value)
}

func (FfiConverterUint16) Write(writer io.Writer, value uint16) {
	writeUint16(writer, value)
}

func (FfiConverterUint16) Lift(value C.uint16_t) uint16 {
	return uint16(value)
}

func (FfiConverterUint16) Read(reader io.Reader) uint16 {
	return readUint16(reader)
}

type FfiDestroyerUint16 struct{}

func (FfiDestroyerUint16) Destroy(_ uint16) {}

type FfiConverterUint32 struct{}

var FfiConverterUint32INSTANCE = FfiConverterUint32{}

func (FfiConverterUint32) Lower(value uint32) C.uint32_t {
	return C.uint32_t(value)
}

func (FfiConverterUint32) Write(writer io.Writer, value uint32) {
	writeUint32(writer, value)
}

func (FfiConverterUint32) Lift(value C.uint32_t) uint32 {
	return uint32(value)
}

func (FfiConverterUint32) Read(reader io.Reader) uint32 {
	return readUint32(reader)
}

type FfiDestroyerUint32 struct{}

func (FfiDestroyerUint32) Destroy(_ uint32) {}

type FfiConverterString struct{}

var FfiConverterStringINSTANCE = FfiConverterString{}

func (FfiConverterString) Lift(rb RustBufferI) string {
	defer rb.Free()
	reader := rb.AsReader()
	b, err := io.ReadAll(reader)
	if err != nil {
		panic(fmt.Errorf("reading reader: %w", err))
	}
	return string(b)
}

func (FfiConverterString) Read(reader io.Reader) string {
	length := readInt32(reader)
	buffer := make([]byte, length)
	read_length, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	if read_length != int(length) {
		panic(fmt.Errorf("bad read length when reading string, expected %d, read %d", length, read_length))
	}
	return string(buffer)
}

func (FfiConverterString) Lower(value string) C.RustBuffer {
	return stringToRustBuffer(value)
}

func (c FfiConverterString) LowerExternal(value string) ExternalCRustBuffer {
	return RustBufferFromC(stringToRustBuffer(value))
}

func (FfiConverterString) Write(writer io.Writer, value string) {
	if len(value) > math.MaxInt32 {
		panic("String is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	write_length, err := io.WriteString(writer, value)
	if err != nil {
		panic(err)
	}
	if write_length != len(value) {
		panic(fmt.Errorf("bad write length when writing string, expected %d, written %d", len(value), write_length))
	}
}

type FfiDestroyerString struct{}

func (FfiDestroyerString) Destroy(_ string) {}

// FFI-safe error type, serializable across the Rust↔Go boundary.
//
// All graph operations and FFI initialization errors map to one of these variants.
// UniFFI requires enum variants to be simple — no nested generics or complex types.
type ActivableError struct {
	err error
}

// Convenience method to turn *ActivableError into error
// Avoiding treating nil pointer as non nil error interface
func (err *ActivableError) AsError() error {
	if err == nil {
		return nil
	} else {
		return err
	}
}

func (err ActivableError) Error() string {
	return fmt.Sprintf("ActivableError: %s", err.err.Error())
}

func (err ActivableError) Unwrap() error {
	return err.err
}

// Err* are used for checking error type with `errors.Is`
var ErrActivableErrorAlreadyInitialized = fmt.Errorf("ActivableErrorAlreadyInitialized")
var ErrActivableErrorNotInitialized = fmt.Errorf("ActivableErrorNotInitialized")
var ErrActivableErrorInvalidInput = fmt.Errorf("ActivableErrorInvalidInput")
var ErrActivableErrorGraphError = fmt.Errorf("ActivableErrorGraphError")
var ErrActivableErrorPoolExhausted = fmt.Errorf("ActivableErrorPoolExhausted")

// Variant structs
// The global runtime was already initialized (second call to `graph_initialize`).
type ActivableErrorAlreadyInitialized struct {
}

// The global runtime was already initialized (second call to `graph_initialize`).
func NewActivableErrorAlreadyInitialized() *ActivableError {
	return &ActivableError{err: &ActivableErrorAlreadyInitialized{}}
}

func (e ActivableErrorAlreadyInitialized) destroy() {
}

func (err ActivableErrorAlreadyInitialized) Error() string {
	return fmt.Sprint("AlreadyInitialized")
}

func (self ActivableErrorAlreadyInitialized) Is(target error) bool {
	return target == ErrActivableErrorAlreadyInitialized
}

// The global runtime is not initialized — `graph_initialize` must be called first.
type ActivableErrorNotInitialized struct {
}

// The global runtime is not initialized — `graph_initialize` must be called first.
func NewActivableErrorNotInitialized() *ActivableError {
	return &ActivableError{err: &ActivableErrorNotInitialized{}}
}

func (e ActivableErrorNotInitialized) destroy() {
}

func (err ActivableErrorNotInitialized) Error() string {
	return fmt.Sprint("NotInitialized")
}

func (self ActivableErrorNotInitialized) Is(target error) bool {
	return target == ErrActivableErrorNotInitialized
}

// Invalid input: JSON deserialization, parameter validation, etc.
type ActivableErrorInvalidInput struct {
	Message string
}

// Invalid input: JSON deserialization, parameter validation, etc.
func NewActivableErrorInvalidInput(
	message string,
) *ActivableError {
	return &ActivableError{err: &ActivableErrorInvalidInput{
		Message: message}}
}

func (e ActivableErrorInvalidInput) destroy() {
	FfiDestroyerString{}.Destroy(e.Message)
}

func (err ActivableErrorInvalidInput) Error() string {
	return fmt.Sprint("InvalidInput",
		": ",

		"Message=",
		err.Message,
	)
}

func (self ActivableErrorInvalidInput) Is(target error) bool {
	return target == ErrActivableErrorInvalidInput
}

// Graph operation failed (query, insert, constraint violation, etc.).
type ActivableErrorGraphError struct {
	Message string
}

// Graph operation failed (query, insert, constraint violation, etc.).
func NewActivableErrorGraphError(
	message string,
) *ActivableError {
	return &ActivableError{err: &ActivableErrorGraphError{
		Message: message}}
}

func (e ActivableErrorGraphError) destroy() {
	FfiDestroyerString{}.Destroy(e.Message)
}

func (err ActivableErrorGraphError) Error() string {
	return fmt.Sprint("GraphError",
		": ",

		"Message=",
		err.Message,
	)
}

func (self ActivableErrorGraphError) Is(target error) bool {
	return target == ErrActivableErrorGraphError
}

// Connection pool exhausted or unable to acquire connection.
type ActivableErrorPoolExhausted struct {
}

// Connection pool exhausted or unable to acquire connection.
func NewActivableErrorPoolExhausted() *ActivableError {
	return &ActivableError{err: &ActivableErrorPoolExhausted{}}
}

func (e ActivableErrorPoolExhausted) destroy() {
}

func (err ActivableErrorPoolExhausted) Error() string {
	return fmt.Sprint("PoolExhausted")
}

func (self ActivableErrorPoolExhausted) Is(target error) bool {
	return target == ErrActivableErrorPoolExhausted
}

type FfiConverterActivableError struct{}

var FfiConverterActivableErrorINSTANCE = FfiConverterActivableError{}

func (c FfiConverterActivableError) Lift(eb RustBufferI) *ActivableError {
	return LiftFromRustBuffer[*ActivableError](c, eb)
}

func (c FfiConverterActivableError) Lower(value *ActivableError) C.RustBuffer {
	return LowerIntoRustBuffer[*ActivableError](c, value)
}

func (c FfiConverterActivableError) LowerExternal(value *ActivableError) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[*ActivableError](c, value))
}

func (c FfiConverterActivableError) Read(reader io.Reader) *ActivableError {
	errorID := readUint32(reader)

	switch errorID {
	case 1:
		return &ActivableError{&ActivableErrorAlreadyInitialized{}}
	case 2:
		return &ActivableError{&ActivableErrorNotInitialized{}}
	case 3:
		return &ActivableError{&ActivableErrorInvalidInput{
			Message: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 4:
		return &ActivableError{&ActivableErrorGraphError{
			Message: FfiConverterStringINSTANCE.Read(reader),
		}}
	case 5:
		return &ActivableError{&ActivableErrorPoolExhausted{}}
	default:
		panic(fmt.Sprintf("Unknown error code %d in FfiConverterActivableError.Read()", errorID))
	}
}

func (c FfiConverterActivableError) Write(writer io.Writer, value *ActivableError) {
	switch variantValue := value.err.(type) {
	case *ActivableErrorAlreadyInitialized:
		writeInt32(writer, 1)
	case *ActivableErrorNotInitialized:
		writeInt32(writer, 2)
	case *ActivableErrorInvalidInput:
		writeInt32(writer, 3)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Message)
	case *ActivableErrorGraphError:
		writeInt32(writer, 4)
		FfiConverterStringINSTANCE.Write(writer, variantValue.Message)
	case *ActivableErrorPoolExhausted:
		writeInt32(writer, 5)
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiConverterActivableError.Write", value))
	}
}

type FfiDestroyerActivableError struct{}

func (_ FfiDestroyerActivableError) Destroy(value *ActivableError) {
	switch variantValue := value.err.(type) {
	case ActivableErrorAlreadyInitialized:
		variantValue.destroy()
	case ActivableErrorNotInitialized:
		variantValue.destroy()
	case ActivableErrorInvalidInput:
		variantValue.destroy()
	case ActivableErrorGraphError:
		variantValue.destroy()
	case ActivableErrorPoolExhausted:
		variantValue.destroy()
	default:
		_ = variantValue
		panic(fmt.Sprintf("invalid error value `%v` in FfiDestroyerActivableError.Destroy", value))
	}
}

type FfiConverterSequenceString struct{}

var FfiConverterSequenceStringINSTANCE = FfiConverterSequenceString{}

func (c FfiConverterSequenceString) Lift(rb RustBufferI) []string {
	return LiftFromRustBuffer[[]string](c, rb)
}

func (c FfiConverterSequenceString) Read(reader io.Reader) []string {
	length := readInt32(reader)
	if length == 0 {
		return nil
	}
	result := make([]string, 0, length)
	for i := int32(0); i < length; i++ {
		result = append(result, FfiConverterStringINSTANCE.Read(reader))
	}
	return result
}

func (c FfiConverterSequenceString) Lower(value []string) C.RustBuffer {
	return LowerIntoRustBuffer[[]string](c, value)
}

func (c FfiConverterSequenceString) LowerExternal(value []string) ExternalCRustBuffer {
	return RustBufferFromC(LowerIntoRustBuffer[[]string](c, value))
}

func (c FfiConverterSequenceString) Write(writer io.Writer, value []string) {
	if len(value) > math.MaxInt32 {
		panic("[]string is too large to fit into Int32")
	}

	writeInt32(writer, int32(len(value)))
	for _, item := range value {
		FfiConverterStringINSTANCE.Write(writer, item)
	}
}

type FfiDestroyerSequenceString struct{}

func (FfiDestroyerSequenceString) Destroy(sequence []string) {
	for _, value := range sequence {
		FfiDestroyerString{}.Destroy(value)
	}
}

const (
	uniffiRustFuturePollReady      int8 = 0
	uniffiRustFuturePollMaybeReady int8 = 1
)

type rustFuturePollFunc func(C.uint64_t, C.UniffiRustFutureContinuationCallback, C.uint64_t)
type rustFutureCompleteFunc[T any] func(C.uint64_t, *C.RustCallStatus) T
type rustFutureFreeFunc func(C.uint64_t)

//export activable_ffi_uniffiFutureContinuationCallback
func activable_ffi_uniffiFutureContinuationCallback(data C.uint64_t, pollResult C.int8_t) {
	h := cgo.Handle(uintptr(data))
	waiter := h.Value().(chan int8)
	waiter <- int8(pollResult)
}

func uniffiRustCallAsync[E any, T any, F any](
	errConverter BufReader[E],
	completeFunc rustFutureCompleteFunc[F],
	liftFunc func(F) T,
	rustFuture C.uint64_t,
	pollFunc rustFuturePollFunc,
	freeFunc rustFutureFreeFunc,
) (T, E) {
	defer freeFunc(rustFuture)

	pollResult := int8(-1)
	waiter := make(chan int8, 1)

	chanHandle := cgo.NewHandle(waiter)
	defer chanHandle.Delete()

	for pollResult != uniffiRustFuturePollReady {
		pollFunc(
			rustFuture,
			(C.UniffiRustFutureContinuationCallback)(C.activable_ffi_uniffiFutureContinuationCallback),
			C.uint64_t(chanHandle),
		)
		pollResult = <-waiter
	}

	var goValue T
	ffiValue, err := rustCallWithError(errConverter, func(status *C.RustCallStatus) F {
		return completeFunc(rustFuture, status)
	})
	if value := reflect.ValueOf(err); value.IsValid() && !value.IsZero() {
		return goValue, err
	}
	return liftFunc(ffiValue), err
}

//export activable_ffi_uniffiFreeGorutine
func activable_ffi_uniffiFreeGorutine(data C.uint64_t) {
	handle := cgo.Handle(uintptr(data))
	defer handle.Delete()

	guard := handle.Value().(chan struct{})
	guard <- struct{}{}
}

// Returns version string from the schema crate.
func Version() string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_activable_ffi_fn_func_version(_uniffiStatus),
		}
	}))
}

// Add a single edge to the graph.
//
// # Arguments
// - `from_id`: Source node ID
// - `to_id`: Target node ID
// - `edge_type`: Edge type (e.g., "ASSUME", "EXECUTE")
// - `properties_json`: JSON object string with edge properties
//
// # Returns
// - Empty string on success
// - Error message string on failure
func AddEdge(fromId string, toId string, edgeType string, propertiesJson string) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_add_edge(FfiConverterStringINSTANCE.Lower(fromId), FfiConverterStringINSTANCE.Lower(toId), FfiConverterStringINSTANCE.Lower(edgeType), FfiConverterStringINSTANCE.Lower(propertiesJson)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Add multiple edges in a batch.
//
// # Arguments
// - `edges_json`: JSON array of edge objects.
// Each object must have: `{from_id, to_id, edge_type, properties}`
//
// # Returns
// - JSON string `{"count": N}` where N is the number of inserted edges
// - JSON string `{"error": "message"}` on failure
func AddEdgesBatch(edgesJson string) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_add_edges_batch(FfiConverterStringINSTANCE.Lower(edgesJson)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Add a single node to the graph.
//
// # Arguments
// - `label`: Node type (e.g., "Principal", "Resource")
// - `id`: Node identifier (typically an ARN or service principal)
// - `properties_json`: JSON object string with node properties
//
// # Returns
// - Empty string on success
// - Error message string on failure
func AddNode(label string, id string, propertiesJson string) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_add_node(FfiConverterStringINSTANCE.Lower(label), FfiConverterStringINSTANCE.Lower(id), FfiConverterStringINSTANCE.Lower(propertiesJson)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Add multiple nodes in a batch.
//
// # Arguments
// - `label`: Node type (all nodes have the same label in this call)
// - `nodes_json`: JSON array of objects, each with properties
//
// # Returns
// - JSON string `{"count": N}` where N is the number of inserted nodes
// - JSON string `{"error": "message"}` on failure
func AddNodesBatch(label string, nodesJson string) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_add_nodes_batch(FfiConverterStringINSTANCE.Lower(label), FfiConverterStringINSTANCE.Lower(nodesJson)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Flush any pending writes (placeholder for future buffering).
//
// Currently a no-op in v1 (writes are immediate).
//
// # Returns
// - Empty string on success
func Flush() string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_activable_ffi_fn_func_flush(_uniffiStatus),
		}
	}))
}

// Initialize the global graph runtime.
//
// Must be called exactly once before any graph operation. Subsequent calls
// return an empty string (success) or error message.
//
// # Arguments
// - `db_host`: PostgreSQL host
// - `db_port`: PostgreSQL port
// - `db_user`: PostgreSQL user
// - `db_password`: PostgreSQL password
// - `db_name`: PostgreSQL database name
// - `max_connections`: Connection pool size
// - `graph_name`: Apache AGE graph name
//
// # Returns
// - Empty string on success
// - Error message string on failure
func GraphInitialize(dbHost string, dbPort uint16, dbUser string, dbPassword string, dbName string, maxConnections uint32, graphName string) string {
	return FfiConverterStringINSTANCE.Lift(rustCall(func(_uniffiStatus *C.RustCallStatus) RustBufferI {
		return GoRustBuffer{
			inner: C.uniffi_activable_ffi_fn_func_graph_initialize(FfiConverterStringINSTANCE.Lower(dbHost), FfiConverterUint16INSTANCE.Lower(dbPort), FfiConverterStringINSTANCE.Lower(dbUser), FfiConverterStringINSTANCE.Lower(dbPassword), FfiConverterStringINSTANCE.Lower(dbName), FfiConverterUint32INSTANCE.Lower(maxConnections), FfiConverterStringINSTANCE.Lower(graphName), _uniffiStatus),
		}
	}))
}

// Health check: verify the connection pool and database are reachable.
//
// # Returns
// - "ok" if the database responds
// - Error message string if the database is unreachable
func HealthCheck() string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_health_check(),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Compute the blast radius from a node.
//
// # Arguments
// - `graph_name`: Apache AGE graph name
// - `node_id`: Center node ID
// - `edge_types`: Edge types to follow (empty = any type)
// - `max_hops`: Maximum depth limit
//
// # Returns
// - JSON array string of reachable NodeRef objects
// - JSON error string on failure
func QueryBlastRadius(graphName string, nodeId string, edgeTypes []string, maxHops uint32) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_query_blast_radius(FfiConverterStringINSTANCE.Lower(graphName), FfiConverterStringINSTANCE.Lower(nodeId), FfiConverterSequenceStringINSTANCE.Lower(edgeTypes), FfiConverterUint32INSTANCE.Lower(maxHops)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Find a node by label and ID.
//
// # Arguments
// - `graph_name`: Apache AGE graph name
// - `label`: Node type (e.g., "Principal", "Resource")
// - `id`: Node identifier
//
// # Returns
// - JSON string with serialized Node object, or null if not found
// - Error message string on failure
func QueryFindNode(graphName string, label string, id string) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_query_find_node(FfiConverterStringINSTANCE.Lower(graphName), FfiConverterStringINSTANCE.Lower(label), FfiConverterStringINSTANCE.Lower(id)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Find all paths between two nodes.
//
// # Arguments
// - `graph_name`: Apache AGE graph name
// - `start_id`: Starting node ID
// - `end_id`: Ending node ID
// - `edge_types`: Edge types to follow (empty = any type)
// - `max_hops`: Maximum path length in hops
//
// # Returns
// - JSON array string of Path objects
// - JSON error string on failure
func QueryPathFinder(graphName string, startId string, endId string, edgeTypes []string, maxHops uint32) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_query_path_finder(FfiConverterStringINSTANCE.Lower(graphName), FfiConverterStringINSTANCE.Lower(startId), FfiConverterStringINSTANCE.Lower(endId), FfiConverterSequenceStringINSTANCE.Lower(edgeTypes), FfiConverterUint32INSTANCE.Lower(maxHops)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Fetch a subgraph around a center node.
//
// # Arguments
// - `graph_name`: Apache AGE graph name
// - `center_id`: Center node ID
// - `radius`: Depth limit for the subgraph
//
// # Returns
// - JSON string with serialized Subgraph object
// - JSON error string on failure
func QuerySubgraph(graphName string, centerId string, radius uint32) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_query_subgraph(FfiConverterStringINSTANCE.Lower(graphName), FfiConverterStringINSTANCE.Lower(centerId), FfiConverterUint32INSTANCE.Lower(radius)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}

// Walk edges from a starting node.
//
// # Arguments
// - `graph_name`: Apache AGE graph name
// - `start_id`: Starting node ID
// - `edge_types`: Edge types to follow (empty = any type)
// - `direction`: "outgoing", "incoming", or "both"
// - `depth`: Maximum depth limit
//
// # Returns
// - JSON array string of NodeRef objects
// - JSON error string on failure
func QueryWalkEdges(graphName string, startId string, edgeTypes []string, direction string, depth uint32) string {
	res, _ := uniffiRustCallAsync[error](
		nil,
		// completeFn
		func(handle C.uint64_t, status *C.RustCallStatus) RustBufferI {
			res := C.ffi_activable_ffi_rust_future_complete_rust_buffer(handle, status)
			return GoRustBuffer{
				inner: res,
			}
		},
		// liftFn
		func(ffi RustBufferI) string {
			return FfiConverterStringINSTANCE.Lift(ffi)
		},
		C.uniffi_activable_ffi_fn_func_query_walk_edges(FfiConverterStringINSTANCE.Lower(graphName), FfiConverterStringINSTANCE.Lower(startId), FfiConverterSequenceStringINSTANCE.Lower(edgeTypes), FfiConverterStringINSTANCE.Lower(direction), FfiConverterUint32INSTANCE.Lower(depth)),
		// pollFn
		func(handle C.uint64_t, continuation C.UniffiRustFutureContinuationCallback, data C.uint64_t) {
			C.ffi_activable_ffi_rust_future_poll_rust_buffer(handle, continuation, data)
		},
		// freeFn
		func(handle C.uint64_t) {
			C.ffi_activable_ffi_rust_future_free_rust_buffer(handle)
		},
	)

	return res
}
