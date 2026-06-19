package mux

import "errors"

// FrameType 表示 mux 层帧类型
type FrameType byte

const (
	FrameTypeOpen  FrameType = 0x01 // 打开逻辑 Stream
	FrameTypeData  FrameType = 0x02 // 传输数据
	FrameTypeClose FrameType = 0x03 // 关闭逻辑 Stream
	FrameTypeError FrameType = 0x04 // 错误通知，MVP 可暂时不用
)

// SessionMode 表示当前 Session 的角色
type SessionMode int

const (
	ModeClient SessionMode = iota
	ModeServer
)

var (
	ErrSessionClosed = errors.New("mux: session closed")
	ErrStreamClosed  = errors.New("mux: stream closed")
	ErrInvalidFrame  = errors.New("mux: invalid frame")
	ErrUnknownStream = errors.New("mux: unknown stream")
)

const (
	DefaultMaxFrameSize = 32 * 1024
	DefaultReadChanSize = 16
	DefaultAcceptSize   = 16
)
