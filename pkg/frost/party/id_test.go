package party

import (
	"reflect"
	"testing"

	"github.com/taurusgroup/frost-ed25519/pkg/internal/scalar"
	"github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

func TestFromBytes(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    ID
		wantErr bool
	}{
		{
			"1",
			args{b: []byte{0, 1}},
			1,
			false,
		},
		{
			"max",
			args{b: []byte{255, 255}},
			65535,
			false,
		},
		{
			"larger size",
			args{b: []byte{0, 1, 0}},
			1,
			false,
		},
		{
			"0",
			args{b: []byte{0, 0, 1}},
			0,
			false,
		},
		{
			"1 byte long",
			args{b: []byte{1}},
			0,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromBytes(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("FromBytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestID_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		p        ID
		wantText []byte
		wantErr  bool
	}{
		{
			"normal",
			42,
			[]byte("42"),
			false,
		},
		{
			"0",
			0,
			[]byte("0"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotText, err := tt.p.MarshalText()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalText() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotText, tt.wantText) {
				t.Errorf("MarshalText() gotText = %v, want %v", gotText, tt.wantText)
			}
		})
	}
}

func TestID_UnmarshalText(t *testing.T) {
	type args struct {
		text []byte
	}
	tests := []struct {
		name    string
		id      ID
		args    args
		wantErr bool
	}{
		{
			"normal",
			42,
			args{text: []byte("42")},
			false,
		},
		{
			"0",
			0,
			args{text: []byte("0")},
			false,
		},
		{
			"max",
			65535,
			args{text: []byte("65535")},
			false,
		},
		{
			"max+1",
			0,
			args{text: []byte("65536")},
			true,
		},
		{
			"nil",
			0,
			args{text: []byte("")},
			true,
		},
		{
			"gibberish",
			0,
			args{text: []byte("dfhg")},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.id.UnmarshalText(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalText() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestID_Lagrange(t *testing.T) {
	N := 16

	partyIDs := make(IDSlice, N)
	for i := range partyIDs {
		partyIDs[i] = ID(i + 1)
	}

	coefficients := make([]*ristretto.Scalar, N)
	sum := ristretto.NewScalar()
	var err error
	for i, id := range partyIDs {
		coefficients[i], err = id.Lagrange(partyIDs)
		if err != nil {
			t.Errorf("Lagrange(): unexpected error: %v", err)
		}
		sum.Add(sum, coefficients[i])
	}
	if scalar.NewScalarUInt32(1).Equal(sum) != 1 {
		t.Errorf("Lagrange(): expected sum of coefficients to be 1")
	}

	type args struct {
		partyIDs IDSlice
	}
	tests := []struct {
		name    string
		id      ID
		args    args
		want    *ristretto.Scalar
		wantErr bool
	}{
		{
			"0 ID",
			0,
			args{partyIDs: partyIDs},
			nil,
			true,
		},
		{
			"not included id",
			42,
			args{partyIDs: partyIDs},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.id.Lagrange(tt.args.partyIDs)
			if (err != nil) != tt.wantErr {
				t.Errorf("Lagrange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Lagrange() got = %v, want %v", got, tt.want)
			}
		})
	}
}
