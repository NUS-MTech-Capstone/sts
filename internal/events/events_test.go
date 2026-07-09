package events

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewPublisherDisabledAndConfigurationErrors(t *testing.T) {
	publisher, err := NewPublisher(context.Background(), false, "", "")
	if err != nil {
		t.Fatalf("NewPublisher(disabled) error = %v", err)
	}
	if _, ok := publisher.(NoopPublisher); !ok {
		t.Fatalf("publisher = %T, want NoopPublisher", publisher)
	}

	if _, err := NewPublisher(context.Background(), true, "ap-southeast-1", ""); err == nil ||
		!strings.Contains(err.Error(), "EVENTS_TOPIC_ARN") {
		t.Fatalf("missing topic error = %v", err)
	}
	if _, err := NewPublisher(context.Background(), true, "", "arn:aws:sns:ap-southeast-1:123456789012:events"); err == nil ||
		!strings.Contains(err.Error(), "AWS_REGION") {
		t.Fatalf("missing region error = %v", err)
	}
}

func TestValidateEventAndNewID(t *testing.T) {
	valid := Event{
		SchemaVersion: SchemaVersion,
		EventID:       "evt-1",
		EventType:     "AccessAllowed",
		Source:        "sts",
		OccurredAt:    time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC),
	}
	if err := validate(valid); err != nil {
		t.Fatalf("validate(valid) error = %v", err)
	}
	for _, event := range []Event{
		{},
		{SchemaVersion: SchemaVersion, EventID: "evt-1", Source: "sts"},
		{SchemaVersion: "wrong", EventID: "evt-1", EventType: "AccessAllowed", Source: "sts"},
	} {
		if err := validate(event); err == nil {
			t.Fatalf("validate(%#v) error = nil", event)
		}
	}
	id := newID()
	if id == "" {
		t.Fatal("newID() returned empty id")
	}
}
