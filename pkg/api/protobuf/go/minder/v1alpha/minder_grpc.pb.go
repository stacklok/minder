//
// Copyright 2023 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.4.0
// - protoc             (unknown)
// source: minder/v1alpha/minder.proto

package v1alpha

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.62.0 or later.
const _ = grpc.SupportPackageIsVersion8

const (
	EvalResultsService_ListEvaluationResults_FullMethodName = "/minder.v1alpha.EvalResultsService/ListEvaluationResults"
	EvalResultsService_ListEvaluationHistory_FullMethodName = "/minder.v1alpha.EvalResultsService/ListEvaluationHistory"
)

// EvalResultsServiceClient is the client API for EvalResultsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type EvalResultsServiceClient interface {
	ListEvaluationResults(ctx context.Context, in *ListEvaluationResultsRequest, opts ...grpc.CallOption) (*ListEvaluationResultsResponse, error)
	ListEvaluationHistory(ctx context.Context, in *ListEvaluationHistoryRequest, opts ...grpc.CallOption) (*ListEvaluationHistoryResponse, error)
}

type evalResultsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewEvalResultsServiceClient(cc grpc.ClientConnInterface) EvalResultsServiceClient {
	return &evalResultsServiceClient{cc}
}

func (c *evalResultsServiceClient) ListEvaluationResults(ctx context.Context, in *ListEvaluationResultsRequest, opts ...grpc.CallOption) (*ListEvaluationResultsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListEvaluationResultsResponse)
	err := c.cc.Invoke(ctx, EvalResultsService_ListEvaluationResults_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *evalResultsServiceClient) ListEvaluationHistory(ctx context.Context, in *ListEvaluationHistoryRequest, opts ...grpc.CallOption) (*ListEvaluationHistoryResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListEvaluationHistoryResponse)
	err := c.cc.Invoke(ctx, EvalResultsService_ListEvaluationHistory_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EvalResultsServiceServer is the server API for EvalResultsService service.
// All implementations must embed UnimplementedEvalResultsServiceServer
// for forward compatibility
type EvalResultsServiceServer interface {
	ListEvaluationResults(context.Context, *ListEvaluationResultsRequest) (*ListEvaluationResultsResponse, error)
	ListEvaluationHistory(context.Context, *ListEvaluationHistoryRequest) (*ListEvaluationHistoryResponse, error)
	mustEmbedUnimplementedEvalResultsServiceServer()
}

// UnimplementedEvalResultsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedEvalResultsServiceServer struct {
}

func (UnimplementedEvalResultsServiceServer) ListEvaluationResults(context.Context, *ListEvaluationResultsRequest) (*ListEvaluationResultsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListEvaluationResults not implemented")
}
func (UnimplementedEvalResultsServiceServer) ListEvaluationHistory(context.Context, *ListEvaluationHistoryRequest) (*ListEvaluationHistoryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListEvaluationHistory not implemented")
}
func (UnimplementedEvalResultsServiceServer) mustEmbedUnimplementedEvalResultsServiceServer() {}

// UnsafeEvalResultsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to EvalResultsServiceServer will
// result in compilation errors.
type UnsafeEvalResultsServiceServer interface {
	mustEmbedUnimplementedEvalResultsServiceServer()
}

func RegisterEvalResultsServiceServer(s grpc.ServiceRegistrar, srv EvalResultsServiceServer) {
	s.RegisterService(&EvalResultsService_ServiceDesc, srv)
}

func _EvalResultsService_ListEvaluationResults_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListEvaluationResultsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EvalResultsServiceServer).ListEvaluationResults(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: EvalResultsService_ListEvaluationResults_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EvalResultsServiceServer).ListEvaluationResults(ctx, req.(*ListEvaluationResultsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _EvalResultsService_ListEvaluationHistory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListEvaluationHistoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EvalResultsServiceServer).ListEvaluationHistory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: EvalResultsService_ListEvaluationHistory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EvalResultsServiceServer).ListEvaluationHistory(ctx, req.(*ListEvaluationHistoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// EvalResultsService_ServiceDesc is the grpc.ServiceDesc for EvalResultsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var EvalResultsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "minder.v1alpha.EvalResultsService",
	HandlerType: (*EvalResultsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListEvaluationResults",
			Handler:    _EvalResultsService_ListEvaluationResults_Handler,
		},
		{
			MethodName: "ListEvaluationHistory",
			Handler:    _EvalResultsService_ListEvaluationHistory_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "minder/v1alpha/minder.proto",
}
