// Code generated by MockGen. DO NOT EDIT.
// Source: ./interface.go
//
// Generated by this command:
//
//	mockgen -package mock_auth -destination=./mock/interface.go -source=./interface.go
//

// Package mock_auth is a generated GoMock package.
package mock_auth

import (
	context "context"
	url "net/url"
	reflect "reflect"

	jwt "github.com/lestrrat-go/jwx/v2/jwt"
	auth "github.com/mindersec/minder/internal/auth"
	gomock "go.uber.org/mock/gomock"
)

// MockResolver is a mock of Resolver interface.
type MockResolver struct {
	ctrl     *gomock.Controller
	recorder *MockResolverMockRecorder
}

// MockResolverMockRecorder is the mock recorder for MockResolver.
type MockResolverMockRecorder struct {
	mock *MockResolver
}

// NewMockResolver creates a new mock instance.
func NewMockResolver(ctrl *gomock.Controller) *MockResolver {
	mock := &MockResolver{ctrl: ctrl}
	mock.recorder = &MockResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResolver) EXPECT() *MockResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockResolver) Resolve(ctx context.Context, id string) (*auth.Identity, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ctx, id)
	ret0, _ := ret[0].(*auth.Identity)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockResolverMockRecorder) Resolve(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockResolver)(nil).Resolve), ctx, id)
}

// Validate mocks base method.
func (m *MockResolver) Validate(ctx context.Context, token jwt.Token) (*auth.Identity, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validate", ctx, token)
	ret0, _ := ret[0].(*auth.Identity)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Validate indicates an expected call of Validate.
func (mr *MockResolverMockRecorder) Validate(ctx, token any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validate", reflect.TypeOf((*MockResolver)(nil).Validate), ctx, token)
}

// MockIdentityProvider is a mock of IdentityProvider interface.
type MockIdentityProvider struct {
	ctrl     *gomock.Controller
	recorder *MockIdentityProviderMockRecorder
}

// MockIdentityProviderMockRecorder is the mock recorder for MockIdentityProvider.
type MockIdentityProviderMockRecorder struct {
	mock *MockIdentityProvider
}

// NewMockIdentityProvider creates a new mock instance.
func NewMockIdentityProvider(ctrl *gomock.Controller) *MockIdentityProvider {
	mock := &MockIdentityProvider{ctrl: ctrl}
	mock.recorder = &MockIdentityProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIdentityProvider) EXPECT() *MockIdentityProviderMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockIdentityProvider) Resolve(ctx context.Context, id string) (*auth.Identity, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", ctx, id)
	ret0, _ := ret[0].(*auth.Identity)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Resolve indicates an expected call of Resolve.
func (mr *MockIdentityProviderMockRecorder) Resolve(ctx, id any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockIdentityProvider)(nil).Resolve), ctx, id)
}

// String mocks base method.
func (m *MockIdentityProvider) String() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "String")
	ret0, _ := ret[0].(string)
	return ret0
}

// String indicates an expected call of String.
func (mr *MockIdentityProviderMockRecorder) String() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "String", reflect.TypeOf((*MockIdentityProvider)(nil).String))
}

// URL mocks base method.
func (m *MockIdentityProvider) URL() url.URL {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "URL")
	ret0, _ := ret[0].(url.URL)
	return ret0
}

// URL indicates an expected call of URL.
func (mr *MockIdentityProviderMockRecorder) URL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "URL", reflect.TypeOf((*MockIdentityProvider)(nil).URL))
}

// Validate mocks base method.
func (m *MockIdentityProvider) Validate(ctx context.Context, token jwt.Token) (*auth.Identity, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validate", ctx, token)
	ret0, _ := ret[0].(*auth.Identity)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Validate indicates an expected call of Validate.
func (mr *MockIdentityProviderMockRecorder) Validate(ctx, token any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validate", reflect.TypeOf((*MockIdentityProvider)(nil).Validate), ctx, token)
}
