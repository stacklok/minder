// Code generated by MockGen. DO NOT EDIT.
// Source: ./cache.go
//
// Generated by this command:
//
//	mockgen -package mock_ratecache -destination=./mock/cache.go -source=./cache.go
//

// Package mock_ratecache is a generated GoMock package.
package mock_ratecache

import (
	reflect "reflect"

	db "github.com/mindersec/minder/internal/db"
	v1 "github.com/mindersec/minder/pkg/providers/v1"
	gomock "go.uber.org/mock/gomock"
)

// MockRestClientCache is a mock of RestClientCache interface.
type MockRestClientCache struct {
	ctrl     *gomock.Controller
	recorder *MockRestClientCacheMockRecorder
	isgomock struct{}
}

// MockRestClientCacheMockRecorder is the mock recorder for MockRestClientCache.
type MockRestClientCacheMockRecorder struct {
	mock *MockRestClientCache
}

// NewMockRestClientCache creates a new mock instance.
func NewMockRestClientCache(ctrl *gomock.Controller) *MockRestClientCache {
	mock := &MockRestClientCache{ctrl: ctrl}
	mock.recorder = &MockRestClientCacheMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRestClientCache) EXPECT() *MockRestClientCacheMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRestClientCache) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockRestClientCacheMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRestClientCache)(nil).Close))
}

// Get mocks base method.
func (m *MockRestClientCache) Get(owner, token string, provider db.ProviderType) (v1.REST, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", owner, token, provider)
	ret0, _ := ret[0].(v1.REST)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockRestClientCacheMockRecorder) Get(owner, token, provider any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRestClientCache)(nil).Get), owner, token, provider)
}

// Set mocks base method.
func (m *MockRestClientCache) Set(owner, token string, provider db.ProviderType, rest v1.REST) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Set", owner, token, provider, rest)
}

// Set indicates an expected call of Set.
func (mr *MockRestClientCacheMockRecorder) Set(owner, token, provider, rest any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Set", reflect.TypeOf((*MockRestClientCache)(nil).Set), owner, token, provider, rest)
}
