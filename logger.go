package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

const (
	LevelCritical = 50
	LevelError    = 40
	LevelWarning  = 30
	LevelInfo     = 20
	LevelDebug    = 10
	LevelNotset   = 0
)

// a wrapper of fmt.Printf
type Logger struct {
	Level int
}

func (l *Logger) printf(level string, format string, a ...interface{}) {
	now := time.Now().Format("2006-01-02 15:04:05.000")
	prefix := now + " [" + level + "] "

	_, file, no, ok := runtime.Caller(2)
	if ok {
		prefix = prefix + "[" + filepath.Base(file) + ":" + strconv.Itoa(no) + "] "
	}

	fmt.Printf(prefix+format, a...)
}

func (l *Logger) Critical(format string, a ...interface{}) {
	if l.Level <= LevelCritical {
		l.printf("CRITICAL", format, a...)
	}
}

func (l *Logger) Error(format string, a ...interface{}) {
	if l.Level <= LevelError {
		l.printf("ERROR", format, a...)
	}
}

func (l *Logger) Warning(format string, a ...interface{}) {
	if l.Level <= LevelWarning {
		l.printf("WARNING", format, a...)
	}
}

func (l *Logger) Info(format string, a ...interface{}) {
	if l.Level <= LevelInfo {
		l.printf("INFO", format, a...)
	}
}

func (l *Logger) Debug(format string, a ...interface{}) {
	if l.Level <= LevelDebug {
		l.printf("DEBUG", format, a...)
	}
}
