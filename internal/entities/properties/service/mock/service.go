// Code generated by MockGen. DO NOT EDIT.
// Source: ./service.go
//
// Generated by this command:
//
//	mockgen -package mock_service -destination=./mock/service.go -source=./service.go
//

// Package mock_service is a generated GoMock package.
package mock_service

import (
	context "context"
	reflect "reflect"

	uuid "github.com/google/uuid"
	db "github.com/stacklok/minder/internal/db"
	models "github.com/stacklok/minder/internal/entities/models"
	properties "github.com/stacklok/minder/internal/entities/properties"
	manager "github.com/stacklok/minder/internal/providers/manager"
	v1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
	v10 "github.com/stacklok/minder/pkg/providers/v1"
	gomock "go.uber.org/mock/gomock"
)

// MockPropertiesService is a mock of PropertiesService interface.
type MockPropertiesService struct {
	ctrl     *gomock.Controller
	recorder *MockPropertiesServiceMockRecorder
}

// MockPropertiesServiceMockRecorder is the mock recorder for MockPropertiesService.
type MockPropertiesServiceMockRecorder struct {
	mock *MockPropertiesService
}

// NewMockPropertiesService creates a new mock instance.
func NewMockPropertiesService(ctrl *gomock.Controller) *MockPropertiesService {
	mock := &MockPropertiesService{ctrl: ctrl}
	mock.recorder = &MockPropertiesServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPropertiesService) EXPECT() *MockPropertiesServiceMockRecorder {
	return m.recorder
}

// EntityForProperties mocks base method.
func (m *MockPropertiesService) EntityForProperties(ctx context.Context, entityID, projectId uuid.UUID, provMan manager.ProviderManager, qtx db.ExtendQuerier) (*models.EntityForProperties, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EntityForProperties", ctx, entityID, projectId, provMan, qtx)
	ret0, _ := ret[0].(*models.EntityForProperties)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EntityForProperties indicates an expected call of EntityForProperties.
func (mr *MockPropertiesServiceMockRecorder) EntityForProperties(ctx, entityID, projectId, provMan, qtx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EntityForProperties", reflect.TypeOf((*MockPropertiesService)(nil).EntityForProperties), ctx, entityID, projectId, provMan, qtx)
}

// ReplaceAllProperties mocks base method.
func (m *MockPropertiesService) ReplaceAllProperties(ctx context.Context, entityID uuid.UUID, props *properties.Properties, qtx db.ExtendQuerier) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReplaceAllProperties", ctx, entityID, props, qtx)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReplaceAllProperties indicates an expected call of ReplaceAllProperties.
func (mr *MockPropertiesServiceMockRecorder) ReplaceAllProperties(ctx, entityID, props, qtx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReplaceAllProperties", reflect.TypeOf((*MockPropertiesService)(nil).ReplaceAllProperties), ctx, entityID, props, qtx)
}

// ReplaceProperty mocks base method.
func (m *MockPropertiesService) ReplaceProperty(ctx context.Context, entityID uuid.UUID, key string, prop *properties.Property, qtx db.ExtendQuerier) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReplaceProperty", ctx, entityID, key, prop, qtx)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReplaceProperty indicates an expected call of ReplaceProperty.
func (mr *MockPropertiesServiceMockRecorder) ReplaceProperty(ctx, entityID, key, prop, qtx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReplaceProperty", reflect.TypeOf((*MockPropertiesService)(nil).ReplaceProperty), ctx, entityID, key, prop, qtx)
}

// RetrieveAllProperties mocks base method.
func (m *MockPropertiesService) RetrieveAllProperties(ctx context.Context, provider v10.Provider, projectId, providerID uuid.UUID, lookupProperties *properties.Properties, entType v1.Entity) (*properties.Properties, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RetrieveAllProperties", ctx, provider, projectId, providerID, lookupProperties, entType)
	ret0, _ := ret[0].(*properties.Properties)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RetrieveAllProperties indicates an expected call of RetrieveAllProperties.
func (mr *MockPropertiesServiceMockRecorder) RetrieveAllProperties(ctx, provider, projectId, providerID, lookupProperties, entType any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RetrieveAllProperties", reflect.TypeOf((*MockPropertiesService)(nil).RetrieveAllProperties), ctx, provider, projectId, providerID, lookupProperties, entType)
}

// RetrieveAllPropertiesForEntity mocks base method.
func (m *MockPropertiesService) RetrieveAllPropertiesForEntity(ctx context.Context, efp *models.EntityForProperties) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RetrieveAllPropertiesForEntity", ctx, efp)
	ret0, _ := ret[0].(error)
	return ret0
}

// RetrieveAllPropertiesForEntity indicates an expected call of RetrieveAllPropertiesForEntity.
func (mr *MockPropertiesServiceMockRecorder) RetrieveAllPropertiesForEntity(ctx, efp any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RetrieveAllPropertiesForEntity", reflect.TypeOf((*MockPropertiesService)(nil).RetrieveAllPropertiesForEntity), ctx, efp)
}

// RetrieveProperty mocks base method.
func (m *MockPropertiesService) RetrieveProperty(ctx context.Context, provider v10.Provider, projectId, providerID uuid.UUID, lookupProperties *properties.Properties, entType v1.Entity, key string) (*properties.Property, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RetrieveProperty", ctx, provider, projectId, providerID, lookupProperties, entType, key)
	ret0, _ := ret[0].(*properties.Property)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RetrieveProperty indicates an expected call of RetrieveProperty.
func (mr *MockPropertiesServiceMockRecorder) RetrieveProperty(ctx, provider, projectId, providerID, lookupProperties, entType, key any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RetrieveProperty", reflect.TypeOf((*MockPropertiesService)(nil).RetrieveProperty), ctx, provider, projectId, providerID, lookupProperties, entType, key)
}

// SaveAllProperties mocks base method.
func (m *MockPropertiesService) SaveAllProperties(ctx context.Context, entityID uuid.UUID, props *properties.Properties, qtx db.ExtendQuerier) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveAllProperties", ctx, entityID, props, qtx)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveAllProperties indicates an expected call of SaveAllProperties.
func (mr *MockPropertiesServiceMockRecorder) SaveAllProperties(ctx, entityID, props, qtx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveAllProperties", reflect.TypeOf((*MockPropertiesService)(nil).SaveAllProperties), ctx, entityID, props, qtx)
}
