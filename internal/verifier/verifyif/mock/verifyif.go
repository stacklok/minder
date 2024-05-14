// Code generated by MockGen. DO NOT EDIT.
// Source: ./verifyif.go
//
// Generated by this command:
//
//	mockgen -package mock_verifyif -destination=./mock/verifyif.go -source=./verifyif.go
//

// Package mock_verifyif is a generated GoMock package.
package mock_verifyif

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
func (m *MockArtifactVerifier) Verify(ctx context.Context, artifactType verifyif.ArtifactType, owner, name, checksumref string) ([]verifyif.Result, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", ctx, artifactType, owner, name, checksumref)
	ret0, _ := ret[0].([]verifyif.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Verify indicates an expected call of Verify.
func (mr *MockArtifactVerifierMockRecorder) Verify(ctx, artifactType, owner, name, checksumref any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockArtifactVerifier)(nil).Verify), ctx, artifactType, owner, name, checksumref)
}

// VerifyContainer mocks base method.
func (m *MockArtifactVerifier) VerifyContainer(ctx context.Context, owner, artifact, checksumref string) ([]verifyif.Result, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyContainer", ctx, owner, artifact, checksumref)
	ret0, _ := ret[0].([]verifyif.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyContainer indicates an expected call of VerifyContainer.
func (mr *MockArtifactVerifierMockRecorder) VerifyContainer(ctx, owner, artifact, checksumref any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyContainer", reflect.TypeOf((*MockArtifactVerifier)(nil).VerifyContainer), ctx, owner, artifact, checksumref)
}
