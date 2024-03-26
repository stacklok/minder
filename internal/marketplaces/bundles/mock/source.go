// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/stacklok/minder/pkg/mindpak/sources (interfaces: BundleSource)
//
// Generated by this command:
//
//	mockgen -package mockbundle -destination internal/marketplaces/bundles/mock/source.go github.com/stacklok/minder/pkg/mindpak/sources BundleSource
//

// Package mockbundle is a generated GoMock package.
package mockbundle

import (
	reflect "reflect"

	mindpak "github.com/stacklok/minder/pkg/mindpak"
	reader "github.com/stacklok/minder/pkg/mindpak/reader"
	gomock "go.uber.org/mock/gomock"
)

// MockBundleSource is a mock of BundleSource interface.
type MockBundleSource struct {
	ctrl     *gomock.Controller
	recorder *MockBundleSourceMockRecorder
}

// MockBundleSourceMockRecorder is the mock recorder for MockBundleSource.
type MockBundleSourceMockRecorder struct {
	mock *MockBundleSource
}

// NewMockBundleSource creates a new mock instance.
func NewMockBundleSource(ctrl *gomock.Controller) *MockBundleSource {
	mock := &MockBundleSource{ctrl: ctrl}
	mock.recorder = &MockBundleSourceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBundleSource) EXPECT() *MockBundleSourceMockRecorder {
	return m.recorder
}

// GetBundle mocks base method.
func (m *MockBundleSource) GetBundle(arg0 mindpak.BundleID) (reader.BundleReader, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBundle", arg0)
	ret0, _ := ret[0].(reader.BundleReader)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBundle indicates an expected call of GetBundle.
func (mr *MockBundleSourceMockRecorder) GetBundle(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBundle", reflect.TypeOf((*MockBundleSource)(nil).GetBundle), arg0)
}

// ListBundles mocks base method.
func (m *MockBundleSource) ListBundles() ([]mindpak.BundleID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListBundles")
	ret0, _ := ret[0].([]mindpak.BundleID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListBundles indicates an expected call of ListBundles.
func (mr *MockBundleSourceMockRecorder) ListBundles() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListBundles", reflect.TypeOf((*MockBundleSource)(nil).ListBundles))
}
