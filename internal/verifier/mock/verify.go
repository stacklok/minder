// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stacklok/minder/internal/verifier/verifyif (interfaces: ArtifactVerifier)
//
// Generated by this command:
//
//	mockgen -package mockverify -destination internal/verifier/mock/verify.go github.com/stacklok/minder/internal/verifier/verifyif ArtifactVerifier
//

// Package mockverify is a generated GoMock package.
package mockverify

import (
	context "context"
	reflect "reflect"

	verifyif "github.com/stacklok/minder/internal/verifier/verifyif"
	gomock "go.uber.org/mock/gomock"
)

// MockArtifactVerifier is a mock of ArtifactVerifier interface.
type MockArtifactVerifier struct {
	ctrl     *gomock.Controller
	recorder *MockArtifactVerifierMockRecorder
}

// MockArtifactVerifierMockRecorder is the mock recorder for MockArtifactVerifier.
type MockArtifactVerifierMockRecorder struct {
	mock *MockArtifactVerifier
}

// NewMockArtifactVerifier creates a new mock instance.
func NewMockArtifactVerifier(ctrl *gomock.Controller) *MockArtifactVerifier {
	mock := &MockArtifactVerifier{ctrl: ctrl}
	mock.recorder = &MockArtifactVerifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockArtifactVerifier) EXPECT() *MockArtifactVerifierMockRecorder {
	return m.recorder
}

// Verify mocks base method.
func (m *MockArtifactVerifier) Verify(arg0 context.Context, arg1 verifyif.ArtifactType, arg2 verifyif.ArtifactRegistry, arg3, arg4, arg5 string) ([]verifyif.Result, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].([]verifyif.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify.
func (mr *MockArtifactVerifierMockRecorder) Verify(arg0, arg1, arg2, arg3, arg4, arg5 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockArtifactVerifier)(nil).Verify), arg0, arg1, arg2, arg3, arg4, arg5)
}

// VerifyContainer mocks base method.
func (m *MockArtifactVerifier) VerifyContainer(arg0 context.Context, arg1, arg2, arg3, arg4 string) ([]verifyif.Result, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyContainer", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].([]verifyif.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyContainer indicates an expected call of VerifyContainer.
func (mr *MockArtifactVerifierMockRecorder) VerifyContainer(arg0, arg1, arg2, arg3, arg4 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyContainer", reflect.TypeOf((*MockArtifactVerifier)(nil).VerifyContainer), arg0, arg1, arg2, arg3, arg4)
}
