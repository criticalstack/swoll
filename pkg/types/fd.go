package types

// used to mark a file-descriptor as an INPUT type, such as:
// bind(<INPUT FD>, ...)
type InputFD int

// used to mark a file-descriptor as an OUTPUT type, such as:
// <OUTPUT FD> = socket(...)
type OutputFD int
