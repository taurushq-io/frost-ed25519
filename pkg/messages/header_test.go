package messages

import (
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
)

func TestHeader_UnmarshalBinary(t *testing.T) {
	type fields struct {
		Type MessageType
		From party.ID
		To   party.ID
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"ok keygen1",
			fields{
				Type: MessageTypeKeyGen1,
				From: 1,
				To:   0,
			},
			args{data: []byte{1, 0, 1, 0, 0}},
			false,
		},
		{
			"bad keygen1",
			fields{
				Type: MessageTypeKeyGen1,
				From: 1,
				To:   2,
			},
			args{data: []byte{1, 0, 1, 0, 2}},
			true,
		},
		{
			"ok keygen2",
			fields{
				Type: MessageTypeKeyGen2,
				From: 2,
				To:   1,
			},
			args{data: []byte{2, 0, 2, 0, 1}},
			false,
		},
		{
			"bad keygen2",
			fields{
				Type: MessageTypeKeyGen2,
				From: 2,
				To:   0,
			},
			args{data: []byte{2, 0, 2, 0, 0}},
			true,
		},
		{
			"ok sign1",
			fields{
				Type: MessageTypeSign1,
				From: 2,
				To:   0,
			},
			args{data: []byte{3, 0, 2, 0, 0}},
			false,
		},
		{
			"bad sign1",
			fields{
				Type: MessageTypeSign1,
				From: 2,
				To:   1,
			},
			args{data: []byte{3, 0, 2, 0, 1}},
			true,
		},
		{
			"ok sign2",
			fields{
				Type: MessageTypeSign2,
				From: 2,
				To:   0,
			},
			args{data: []byte{4, 0, 2, 0, 0}},
			false,
		},
		{
			"bad sign2",
			fields{
				Type: MessageTypeSign2,
				From: 2,
				To:   1,
			},
			args{data: []byte{4, 0, 2, 0, 1}},
			true,
		},
		{
			"bad type",
			fields{
				Type: 0,
				From: 2,
				To:   1,
			},
			args{data: []byte{4, 0, 2, 0, 1}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Header{
				Type: tt.fields.Type,
				From: tt.fields.From,
				To:   tt.fields.To,
			}
			h2 := &Header{}
			err := h2.UnmarshalBinary(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && !h.Equal(h2) {
				t.Errorf("UnmarshalBinary() got = %v, want %v", h2, h)
			}
		})
	}
}
