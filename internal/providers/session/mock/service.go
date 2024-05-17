// Code generated by MockGen. DO NOT EDIT.
// Source: ./service.go
//
// Generated by this command:
//
//	mockgen -package mock_session -destination=./mock/service.go -source=./service.go
//

// Package mock_session is a generated GoMock package.
package mock_session

import (
	context "context"
	reflect "reflect"

	uuid "github.com/google/uuid"
	crypto "github.com/stacklok/minder/internal/crypto"
	db "github.com/stacklok/minder/internal/db"
	gomock "go.uber.org/mock/gomock"
)

// MockProviderSessionService is a mock of ProviderSessionService interface.
type MockProviderSessionService struct {
	ctrl     *gomock.Controller
	recorder *MockProviderSessionServiceMockRecorder
}

// MockProviderSessionServiceMockRecorder is the mock recorder for MockProviderSessionService.
type MockProviderSessionServiceMockRecorder struct {
	mock *MockProviderSessionService
}

// NewMockProviderSessionService creates a new mock instance.
func NewMockProviderSessionService(ctrl *gomock.Controller) *MockProviderSessionService {
	mock := &MockProviderSessionService{ctrl: ctrl}
	mock.recorder = &MockProviderSessionServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProviderSessionService) EXPECT() *MockProviderSessionServiceMockRecorder {
	return m.recorder
}

// CreateProviderFromSessionState mocks base method.
func (m *MockProviderSessionService) CreateProviderFromSessionState(ctx context.Context, providerClass db.ProviderClass, encryptedCreds *crypto.EncryptedData, state string) (*db.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateProviderFromSessionState", ctx, providerClass, encryptedCreds, state)
	ret0, _ := ret[0].(*db.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateProviderFromSessionState indicates an expected call of CreateProviderFromSessionState.
func (mr *MockProviderSessionServiceMockRecorder) CreateProviderFromSessionState(ctx, providerClass, encryptedCreds, state any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateProviderFromSessionState", reflect.TypeOf((*MockProviderSessionService)(nil).CreateProviderFromSessionState), ctx, providerClass, encryptedCreds, state)
}

// MockproviderByNameGetter is a mock of providerByNameGetter interface.
type MockproviderByNameGetter struct {
	ctrl     *gomock.Controller
	recorder *MockproviderByNameGetterMockRecorder
}

// MockproviderByNameGetterMockRecorder is the mock recorder for MockproviderByNameGetter.
type MockproviderByNameGetterMockRecorder struct {
	mock *MockproviderByNameGetter
}

// NewMockproviderByNameGetter creates a new mock instance.
func NewMockproviderByNameGetter(ctrl *gomock.Controller) *MockproviderByNameGetter {
	mock := &MockproviderByNameGetter{ctrl: ctrl}
	mock.recorder = &MockproviderByNameGetterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockproviderByNameGetter) EXPECT() *MockproviderByNameGetterMockRecorder {
	return m.recorder
}

// GetByName mocks base method.
func (m *MockproviderByNameGetter) GetByName(ctx context.Context, projectID uuid.UUID, name string) (*db.Provider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByName", ctx, projectID, name)
	ret0, _ := ret[0].(*db.Provider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByName indicates an expected call of GetByName.
func (mr *MockproviderByNameGetterMockRecorder) GetByName(ctx, projectID, name any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByName", reflect.TypeOf((*MockproviderByNameGetter)(nil).GetByName), ctx, projectID, name)
}

// MockdbSessionStore is a mock of dbSessionStore interface.
type MockdbSessionStore struct {
	ctrl     *gomock.Controller
	recorder *MockdbSessionStoreMockRecorder
}

// MockdbSessionStoreMockRecorder is the mock recorder for MockdbSessionStore.
type MockdbSessionStoreMockRecorder struct {
	mock *MockdbSessionStore
}

// NewMockdbSessionStore creates a new mock instance.
func NewMockdbSessionStore(ctrl *gomock.Controller) *MockdbSessionStore {
	mock := &MockdbSessionStore{ctrl: ctrl}
	mock.recorder = &MockdbSessionStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockdbSessionStore) EXPECT() *MockdbSessionStoreMockRecorder {
	return m.recorder
}

// GetProjectIDBySessionState mocks base method.
func (m *MockdbSessionStore) GetProjectIDBySessionState(ctx context.Context, sessionState string) (db.GetProjectIDBySessionStateRow, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProjectIDBySessionState", ctx, sessionState)
	ret0, _ := ret[0].(db.GetProjectIDBySessionStateRow)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetProjectIDBySessionState indicates an expected call of GetProjectIDBySessionState.
func (mr *MockdbSessionStoreMockRecorder) GetProjectIDBySessionState(ctx, sessionState any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProjectIDBySessionState", reflect.TypeOf((*MockdbSessionStore)(nil).GetProjectIDBySessionState), ctx, sessionState)
}

// UpsertAccessToken mocks base method.
func (m *MockdbSessionStore) UpsertAccessToken(ctx context.Context, arg db.UpsertAccessTokenParams) (db.ProviderAccessToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpsertAccessToken", ctx, arg)
	ret0, _ := ret[0].(db.ProviderAccessToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpsertAccessToken indicates an expected call of UpsertAccessToken.
func (mr *MockdbSessionStoreMockRecorder) UpsertAccessToken(ctx, arg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpsertAccessToken", reflect.TypeOf((*MockdbSessionStore)(nil).UpsertAccessToken), ctx, arg)
}
