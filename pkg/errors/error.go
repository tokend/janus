/*
Package errors provides a nice way of handling http errors

Examples:
To create an error:
	err := errors.New(http.StatusBadRequest, "Something went wrong")
*/
package errors

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"

	"github.com/hellofresh/janus/pkg/render"
	baseErrors "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	// ErrRouteNotFound happens when no route was matched
	ErrRouteNotFound = New(http.StatusNotFound, "Not Found")
	// ErrInvalidID represents an invalid identifier
	ErrInvalidID = New(http.StatusBadRequest, "please provide a valid ID")
)

// Error is a custom error that implements the `error` interface.
// When creating errors you should provide a code (could be and http status code)
// and a message, this way we can handle the errors in a centralized place.
type Error struct {
	Status    string    `json:"status"`
	Title string     `json:"title"`
}

type Errors struct {
	Errors []Error `json:"errors"`
}

// New creates a new instance of Error
func New(code int, message string) *Error {
	return &Error{strconv.Itoa(code), message}
}

func (e *Error) Error() string {
	return e.Title
}

// NotFound handler is called when no route is matched
func NotFound(w http.ResponseWriter, r *http.Request) {
	Handler(w, ErrRouteNotFound)
}

// RecoveryHandler handler is used when a panic happens
func RecoveryHandler(w http.ResponseWriter, r *http.Request, err interface{}) {
	Handler(w, err)
}

// Handler marshals an error to JSON, automatically escaping HTML and setting the
// Content-Type as application/json.
func Handler(w http.ResponseWriter, err interface{}) {
	errors := Errors{}
	switch internalErr := err.(type) {
	case *Error:
		log.WithFields(log.Fields{
			"code":       internalErr.Status,
			log.ErrorKey: internalErr.Error(),
		}).Info("Internal error handled")

		errors.Errors = append(errors.Errors, *internalErr)
		status, err := strconv.Atoi(internalErr.Status)
		if err != nil {
			log.Debug(fmt.Sprintf("failed to parse error code. error: %s . code: %s", internalErr.Title, internalErr.Status))
			render.JSON(w, http.StatusInternalServerError, errors)
		}
		render.JSON(w, status, errors)
	case error:
		log.WithError(internalErr).WithField("stack", string(debug.Stack())).Error("Internal server error handled")
		errors.Errors = append(errors.Errors, Error{Status: strconv.Itoa(http.StatusInternalServerError), Title: internalErr.Error()})
		render.JSON(w, http.StatusInternalServerError, errors)
	default:
		log.WithFields(log.Fields{
			log.ErrorKey: err,
			"stack":      string(debug.Stack()),
		}).Error("Internal server error handled")
		errors.Errors = append(errors.Errors, Error{Status: strconv.Itoa(http.StatusInternalServerError), Title: "Internal Error"})
		render.JSON(w, http.StatusInternalServerError, errors)
	}
}

// Wrap returns an error annotating err with a stack trace
// at the point Wrap is called, and the supplied message.
// If err is nil, Wrap returns nil.
func Wrap(err error, message string) error {
	return baseErrors.Wrap(err, message)
}
