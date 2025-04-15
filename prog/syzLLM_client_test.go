package prog

import (
	"reflect"
	"strings"
	"testing"
)

func TestHaveResTag(t *testing.T) {
	tests := []struct {
		name string
		call string
		want bool
	}{
		{"WithTags", "@RSTART@content@REND@", true},
		{"WithoutTags", "content", false},
		{"OnlyStartTag", "@RSTART@content", false},
		{"OnlyEndTag", "content@REND@", false},
		{"NoContentWithTags", "@RSTART@@REND@", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HaveResTag(tt.call); got != tt.want {
				t.Errorf("HaveResTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractCallNameFromCallWithinTags(t *testing.T) {
	tests := []struct {
		name       string
		call       string
		want       string
		wantErr    bool
		wantErrMsg string
	}{
		{"ValidCallWithoutRes", "recvfrom$unix(@RSTART@sendto$llc()@REND@)", "recvfrom", false, ""},
		{"validCallWithoutDescriptor", "munmap(&(0x7f70c6aea000)=nil, 0x40000)", "munmap", false, ""},
		{"EmptyCall", "", "", true, "Wrong syscall: no brackets"},
		{"NoParentheses", "functionName arg1, arg2", "", true, "Wrong syscall: no brackets"},
		//This method is used for extract call name from calls matched within res tags, so will not have calls start with r0 = ...
		//{"ValidCallWithRes", "r0 = sendto$llc(@RSTART@openat$damon_target_ids()@REND@)", "sendto", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if tt.wantErr {
						if err, ok := r.(error); ok && err.Error() != tt.wantErrMsg {
							t.Errorf("ExtractCallName() panic with wrong error message: got %v, want %v", err.Error(), tt.wantErrMsg)
						}
						return
					}
					t.Errorf("ExtractCallName() caused an unexpected panic for input %v", tt.call)
				}
			}()

			got := ExtractCallNameFromCallWithinTags(tt.call)
			if got != tt.want {
				t.Errorf("ExtractCallName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasResource(t *testing.T) {
	tests := []struct {
		name string
		call string
		want int
	}{
		{"HasResource", "r0 = sendto$llc()", 1},
		{"NoResource", "poll(@RSTART@sendto$llc()@REND@)", 0},
		{"NonResourceStart", "recvfrom$unix()", 0},
		{"Pipe", "pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})", 2},
		{"EmptyString", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasResource(tt.call); got != tt.want {
				t.Errorf("HasResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractResourceNumber(t *testing.T) {
	tests := []struct {
		name       string
		call       string
		wantNum    int
		wantBool   bool
		wantErr    bool
		wantErrMsg string
	}{
		{"HasResource", "r0 = sendto$llc()", 0, true, false, ""},
		{"NoResource", "poll(@RSTART@sendto$llc()@REND@)", -1, false, false, ""},
		{"RStartButNoResource", "recvfrom$unix()", -1, false, false, ""},
		{"EmptyString", "", -1, false, false, ""},
		{"InvalidNumber", "rUnix = ", -1, false, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if tt.wantErr {
						if err, ok := r.(error); ok && err.Error() != tt.wantErrMsg {
							t.Errorf("ExtractResourceNumber() panic with wrong error message: got %v, want %v", err.Error(), tt.wantErrMsg)
						}
						return
					}
					t.Errorf("ExtractResourceNumber() caused an unexpected panic for input %v", tt.call)
				}
			}()

			gotNum, gotBool := ExtractResourceNumber(tt.call)
			if gotNum != tt.wantNum || gotBool != tt.wantBool {
				t.Errorf("ExtractResourceNumber() gotNum = %v, gotBool = %v, wantNum = %v, wantBool = %v", gotNum, gotBool, tt.wantNum, tt.wantBool)
			}
		})
	}
}

func TestAssignResource(t *testing.T) {
	testCases := []struct {
		name   string
		call   string
		resNum int
		want   string
	}{
		{"ValidResource", "r0 = sendto$llc()", 5, "r5 = sendto$llc()"},
		{"ValidResource", "r10 = write$damon_target_ids(@RSTART@openat$damon_target_ids(0xffffffffffffff9c, &(0x7f0000008000)=nil, 0xa0042, 0x1a4))", 16, "r16 = write$damon_target_ids(@RSTART@openat$damon_target_ids(0xffffffffffffff9c, &(0x7f0000008000)=nil, 0xa0042, 0x1a4))"},
		{"NoResource", "close()", 3, "close()"},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := AssignResource(tt.call, tt.resNum); got != tt.want {
				t.Errorf("AssignResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateResourceCount(t *testing.T) {
	tests := []struct {
		name                string
		paramCall           string
		paramCalls          []string
		paramInsertPosition int
		paramHasProvider    bool
		wantCall            string
		wantCalls           []string
	}{
		{"NoProvider", "r0 = sendto$llc()", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, false, "r1 = sendto$llc()", []string{"r0 = openat()", "read(r0)", "r1 = sendto$llc()", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"HasProvider", "r0 = sendto$llc()", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, true, "r2 = sendto$llc()", []string{"r0 = openat()", "read(r0)", "r2 = sendto$llc()", "r3 = close(r0)", "r4 = write$unix(r3)"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UpdateResourceCount(tt.paramCall, tt.paramCalls, tt.paramInsertPosition, tt.paramHasProvider, 0); got != tt.wantCall || !isEqual(tt.paramCalls, tt.wantCalls) {
				t.Errorf("UpdateResourceCount() = %v, want %v, \nparamCalls %v, \nwantCalls %v", got, tt.wantCall, tt.paramCalls, tt.wantCalls)
			}
		})
	}
}

func TestReplaceContentWithinTags(t *testing.T) {
	tests := []struct {
		name      string
		paramCall string
		want      string
	}{
		{"NestedResources", "sendto$llc(@RSTART@sendto$llc(@RSTART@sendto$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xda, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "sendto$llc(r0, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)"},
	}

	replacer := func(match string) string {
		matchWithoutTags := match
		if strings.HasPrefix(matchWithoutTags, RPrefix) && strings.HasSuffix(matchWithoutTags, RSuffix) {
			return "r0"
		} else {
			return match
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReplaceContentWithinTags(tt.paramCall, replacer); got != tt.want {
				t.Errorf("ReplaceContentWithinTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractResourceIDs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "SingleResource",
			input:    "<r0=>0xffffffffffffffff",
			expected: []string{"r0"},
		},
		{
			name:     "TwoResources",
			input:    "pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})",
			expected: []string{"r0", "r1"},
		},
		{
			name:     "NoResources",
			input:    "openat()",
			expected: []string{},
		},
		{
			name:     "InvalidResource",
			input:    "<rX=>",
			expected: []string{},
		},
		{
			name:     "MultipleOccurrences",
			input:    "<r2=>data,<r2=>more",
			expected: []string{"r2", "r2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractResourceIDs(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ExtractResourceIDs(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestHasPipeBeforeInsertPosition(t *testing.T) {
	tests := []struct {
		name             string
		calls            []string
		insertPosition   int
		wantHas          bool
		wantReplacements []string
	}{
		{
			name:             "PipeBefore",
			calls:            []string{"openat()", "pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})", "read(r0)"},
			insertPosition:   2,
			wantHas:          true,
			wantReplacements: []string{"r0", "r1"},
		},
		{
			name:             "NoPipeBefore",
			calls:            []string{"openat()", "read(r0)", "close(r0)"},
			insertPosition:   2,
			wantHas:          false,
			wantReplacements: nil,
		},
		{
			name:             "InsertAtZero",
			calls:            []string{"openat()", "pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})"},
			insertPosition:   0,
			wantHas:          false,
			wantReplacements: nil,
		},
		{
			name:             "OutOfBounds",
			calls:            []string{"openat()"},
			insertPosition:   5,
			wantHas:          false,
			wantReplacements: nil,
		},
		{
			name:             "EmptyCalls",
			calls:            []string{},
			insertPosition:   0,
			wantHas:          false,
			wantReplacements: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, replacements := HasPipeBeforeInsertPosition(tt.calls, tt.insertPosition)
			if has != tt.wantHas || !reflect.DeepEqual(replacements, tt.wantReplacements) {
				t.Errorf("HasPipeBeforeInsertPosition(%v, %d) = (%v, %v), want (%v, %v)",
					tt.calls, tt.insertPosition, has, replacements, tt.wantHas, tt.wantReplacements)
			}
		})
	}
}

func TestReplaceMultipleBetween(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		prefix       string
		suffix       string
		replacements []string
		expected     string
	}{
		{
			name:         "TwoReplacements",
			input:        "poll([{@START@pipe()@END@}, {@START@pipe()@END@}])",
			prefix:       "@START@",
			suffix:       "@END@",
			replacements: []string{"r1", "r2"},
			expected:     "poll([{r1}, {r2}])",
		},
		{
			name:         "SingleReplacement",
			input:        "read(@START@pipe()@END@, data)",
			prefix:       "@START@",
			suffix:       "@END@",
			replacements: []string{"r3"},
			expected:     "read(r3, data)",
		},
		{
			name:         "NoPrefix",
			input:        "read(data)",
			prefix:       "@START@",
			suffix:       "@END@",
			replacements: []string{"r1"},
			expected:     "read(data)",
		},
		{
			name:         "NoSuffix",
			input:        "read(@START@pipe())",
			prefix:       "@START@",
			suffix:       "@END@",
			replacements: []string{"r1"},
			expected:     "read(@START@pipe())",
		},
		{
			name:         "MoreReplacementsThanPairs",
			input:        "read(@START@pipe()@END@)",
			prefix:       "@START@",
			suffix:       "@END@",
			replacements: []string{"r1", "r2", "r3"},
			expected:     "read(r1)",
		},
		{
			name:         "EmptyInput",
			input:        "",
			prefix:       "@START@",
			suffix:       "@END@",
			replacements: []string{"r1"},
			expected:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReplaceMultipleBetween(tt.input, tt.prefix, tt.suffix, tt.replacements)
			if got != tt.expected {
				t.Errorf("ReplaceMultipleBetween(%q, %q, %q, %v) = %q, want %q",
					tt.input, tt.prefix, tt.suffix, tt.replacements, got, tt.expected)
			}
		})
	}
}

func TestGetNextResource(t *testing.T) {
	tests := []struct {
		name           string
		calls          []string
		insertPosition int
		expected       int
	}{
		{
			name:           "ResourcesBefore",
			calls:          []string{"r0 = openat()", "r1 = pipe()", "read(r0)"},
			insertPosition: 2,
			expected:       2,
		},
		{
			name:           "NoResources",
			calls:          []string{"openat()", "read()", "close()"},
			insertPosition: 2,
			expected:       0,
		},
		{
			name:           "InsertAtStart",
			calls:          []string{"r0 = openat()", "r2 = pipe()"},
			insertPosition: 0,
			expected:       0,
		},
		{
			name:           "OutOfBounds",
			calls:          []string{"r1 = openat()"},
			insertPosition: 5,
			expected:       2,
		},
		{
			name:           "EmptyCalls",
			calls:          []string{},
			insertPosition: 0,
			expected:       0,
		},
		{
			name:           "InvalidResource",
			calls:          []string{"rx = openat()", "r3 = pipe()"},
			insertPosition: 2,
			expected:       4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetNextResource(tt.calls, tt.insertPosition)
			if got != tt.expected {
				t.Errorf("GetNextResource(%v, %d) = %d, want %d",
					tt.calls, tt.insertPosition, got, tt.expected)
			}
		})
	}
}

func TestUpdateResourceNumbers(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		nextResource    int
		numNewResources int
		expected        string
	}{
		{
			name:            "UpdateHigherResources",
			input:           "read(r0, r1, r2)",
			nextResource:    1,
			numNewResources: 2,
			expected:        "read(r0, r3, r4)",
		},
		{
			name:            "NoUpdateNeeded",
			input:           "read(r0)",
			nextResource:    2,
			numNewResources: 2,
			expected:        "read(r0)",
		},
		{
			name:            "MultipleOccurrences",
			input:           "write(r1, r1, r3)",
			nextResource:    1,
			numNewResources: 2,
			expected:        "write(r3, r3, r5)",
		},
		{
			name:            "NoResources",
			input:           "close()",
			nextResource:    1,
			numNewResources: 2,
			expected:        "close()",
		},
		{
			name:            "InvalidResource",
			input:           "read(rx)",
			nextResource:    1,
			numNewResources: 2,
			expected:        "read(rx)",
		},
		{
			name:            "EmptyInput",
			input:           "",
			nextResource:    1,
			numNewResources: 2,
			expected:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := updateResourceNumbers(tt.input, tt.nextResource, tt.numNewResources)
			if got != tt.expected {
				t.Errorf("updateResourceNumbers(%q, %d, %d) = %q, want %q",
					tt.input, tt.nextResource, tt.numNewResources, got, tt.expected)
			}
		})
	}
}

func TestParsePipeResource(t *testing.T) {
	tests := []struct {
		name                string
		paramCall           string
		paramCalls          []string
		paramInsertPosition int
		want                []string
	}{
		{
			"NoPipe",
			"epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x2, @RSTART@openat$damon_target_ids(0xffffffffffffff9c, &(0x7f0000008000)='./file0\\x00', 0x241, 0x180)@REND@, &(0x7f000003a000)={0x1, 0x4C})",
			[]string{"r0 = openat()", "read(r0)", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x2, @RSTART@openat$damon_target_ids(0xffffffffffffff9c, &(0x7f0000008000)='./file0\\x00', 0x241, 0x180)@REND@, &(0x7f000003a000)={0x1, 0x4C})", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x2, @RSTART@openat$damon_target_ids(0xffffffffffffff9c, &(0x7f0000008000)='./file0\\x00', 0x241, 0x180)@REND@, &(0x7f000003a000)={0x1, 0x4C})", "r1 = close(r0)", "r2 = write$unix(r1)"},
		},
		{
			"ReadOnePipe",
			"read(@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f0000055000)=\"\"/0x400, 0xa)",
			[]string{"r0 = openat()", "read(r0)", "read(@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f0000055000)=\"\"/0x400, 0xa)", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "read(r1, &(0x7f0000055000)=\"\"/0x400, 0xa)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
		{
			"EpollOnePipe",
			"epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})",
			[]string{"r0 = openat()", "read(r0)", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, r1, &(0x7f000003a000)={0x1, 0x10})", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
		{
			"PollTwoPipes",
			"poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}], 0x2, 0x3e0)",
			[]string{"r0 = openat()", "read(r0)", "poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}], 0x2, 0x3e0)", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "poll(&(0x7f0000080000)=[{r1}, {r2}], 0x2, 0x3e0)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
		{
			"SpliceTwoPipes",
			"splice(@PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e2000)=nil, @PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e6000)=nil, 0x10000, 0x5)",
			[]string{"r0 = openat()", "read(r0)", "splice(@PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e2000)=nil, @PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e6000)=nil, 0x10000, 0x5)", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f00000d7000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "splice(r1, &(0x7f00000e2000)=nil, r2, &(0x7f00000e6000)=nil, 0x10000, 0x5)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
		{
			"AlreadyHasPipe",
			"splice(@PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e2000)=nil, @PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e6000)=nil, 0x10000, 0x5)",
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f00000d7000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "splice(@PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e2000)=nil, @PIPESTART@pipe(&(0x7f00000d7000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e6000)=nil, 0x10000, 0x5)", "r3 = close(r0)", "r4 = write$unix(r3)"},
			3,
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f00000d7000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "splice(r1, &(0x7f00000e2000)=nil, r2, &(0x7f00000e6000)=nil, 0x10000, 0x5)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
		{
			"ReadPipe2",
			"read$FUSE(@PIPESTART@pipe2(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x80800)@PIPEEND@, &(0x7f0000055000)=\"\"/0x400, 0x400)",
			[]string{"r0 = openat()", "read(r0)", "read$FUSE(@PIPESTART@pipe2(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x80800)@PIPEEND@, &(0x7f0000055000)=\"\"/0x400, 0x400)", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe2(&(0x7f0000000240)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff}, 0x80800)", "read$FUSE(r1, &(0x7f0000055000)=\"\"/0x400, 0x400)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
		{
			"pollPipe2",
			"poll(&(0x7f0000080000)=[{@PIPESTART@pipe2(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x80000)@PIPEEND@}, {@PIPESTART@pipe2(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x80000)@PIPEEND@}], 0x2, 0xffffffffffffffff)",
			[]string{"r0 = openat()", "read(r0)", "poll(&(0x7f0000080000)=[{@PIPESTART@pipe2(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x80000)@PIPEEND@}, {@PIPESTART@pipe2(&(0x7f0000000240)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff}, 0x80000)@PIPEEND@}], 0x2, 0xffffffffffffffff)", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe2(&(0x7f0000000240)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff}, 0x80000)", "poll(&(0x7f0000080000)=[{r1}, {r2}], 0x2, 0xffffffffffffffff)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePipeResource(tt.paramCall, tt.paramCalls, tt.paramInsertPosition); !isEqual(got, tt.want) {
				t.Errorf("ParsePipeResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSingleResource(t *testing.T) {
	tests := []struct {
		name                string
		paramCall           string
		paramCalls          []string
		paramInsertPosition int
		want                []string
	}{
		{"ResCallWithResArgsWithProvidedRes", "r0 = sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "r1 = sendto$llc(r0, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"ResCallWithResArgsNoProvidedRes", "r0 = sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = socket()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "r1 = openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)", "r2 = sendto$llc(r1, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r3 = close(r0)", "r4 = write$unix(r3)"}},
		{"ResCallNoResArgsNoProvidedRes", "r0 = sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "r1 = sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"NoResCallWithResArgsWithProvidedRes", "sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "sendto$llc(r0, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r1 = close(r0)", "r2 = write$unix(r1)"}},
		{"NoResCallWithResArgsNoProvidedRes", "sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = socket()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "r1 = openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)", "sendto$llc(r1, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"NoResCallNoResArgsNoProvidedRes", "sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r1 = close(r0)", "r2 = write$unix(r1)"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseSingleResource(tt.paramCall, tt.paramCalls, tt.paramInsertPosition, 0); !isEqual(got, tt.want) {
				t.Errorf("ParseSingleResource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseNestedResources(t *testing.T) {
	tests := []struct {
		name                string
		paramCall           string
		paramCalls          []string
		paramInsertPosition int
		want                []string
	}{
		{"ResCallWithResArgsWithProvidedRes", "r0 = sendto$llc(@RSTART@openat(@RSTART@openat(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xda, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "r1 = sendto$llc(r0, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"ResCallWithResArgsNoProvidedRes", "r0 = sendto$llc(@RSTART@openat(@RSTART@openat(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xda, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = socket()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "r1 = openat(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)", "r2 = openat(r1, &(0x7f0000014000)='\\x00'/64, 0xda, 0x40, 0x0, 0x0)", "r3 = sendto$llc(r2, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r4 = close(r0)", "r5 = write$unix(r4)"}},
		{"ResCallNoResArgsNoProvidedRes", "r0 = sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "r1 = sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"NoResCallWithResArgsWithProvidedRes", "sendto$llc(@RSTART@openat(@RSTART@openat(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xda, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "sendto$llc(r0, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r1 = close(r0)", "r2 = write$unix(r1)"}},
		{"NoResCallWithResArgsNoProvidedRes", "sendto$llc(@RSTART@openat(@RSTART@openat(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xda, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = socket()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "r1 = openat(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)", "r2 = openat(r1, &(0x7f0000014000)='\\x00'/64, 0xda, 0x40, 0x0, 0x0)", "sendto$llc(r2, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r3 = close(r0)", "r4 = write$unix(r3)"}},
		{"NoResCallNoResArgsNoProvidedRes", "sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "sendto$llc(PLACEHOLDER, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r1 = close(r0)", "r2 = write$unix(r1)"}},
		{"ResCallWithNoNestedResArgsWithProvidedRes", "r0 = sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "r1 = sendto$llc(r0, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"ResCallWithNoNestedResArgsNoProvidedRes", "r0 = sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = socket()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "r1 = openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)", "r2 = sendto$llc(r1, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r3 = close(r0)", "r4 = write$unix(r3)"}},
		{"NoResCallWithResArgsWithProvidedRes", "sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = openat()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = openat()", "read(r0)", "sendto$llc(r0, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r1 = close(r0)", "r2 = write$unix(r1)"}},
		{"NoResCallWithNoNestedResArgsNoProvidedRes", "sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = socket()", "read(r0)", "r0 = sendto$llc()", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "r1 = openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)", "sendto$llc(r1, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r2 = close(r0)", "r3 = write$unix(r2)"}},
		{"OnePipe", "read(@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f0000055000)=\"\"/0x400, 0xa)", []string{"r0 = socket()", "read(r0)", "read(@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f0000055000)=\"\"/0x400, 0xa)", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "read(r1, &(0x7f0000055000)=\"\"/0x400, 0xa)", "r3 = close(r0)", "r4 = write$unix(r3)"}},
		{"TwoPipes", "poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}], 0x2, 0x3e0)", []string{"r0 = socket()", "read(r0)", "poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}], 0x2, 0x3e0)", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "poll(&(0x7f0000080000)=[{r1}, {r2}], 0x2, 0x3e0)", "r3 = close(r0)", "r4 = write$unix(r3)"}},
		{"ResAndPipe", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})", []string{"r0 = socket()", "read(r0)", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})", "r1 = close(r0)", "r2 = write$unix(r1)"}, 2, []string{"r0 = socket()", "read(r0)", "r1 = epoll_create1(0x80000)", "pipe(&(0x7f0000064000)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})", "epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, &(0x7f000003a000)={0x1, 0x10})", "r4 = close(r0)", "r5 = write$unix(r4)"}},
		{"TwoPipesAndAlreadyHasPipe", "poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}], 0x2, 0x3e0)", []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@}], 0x2, 0x3e0)", "r3 = close(r0)", "r4 = write$unix(r3)"}, 3, []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "poll(&(0x7f0000080000)=[{r1}, {r2}], 0x2, 0x3e0)", "r3 = close(r0)", "r4 = write$unix(r3)"}},
		{"ResAndAlreadyHasPipe", "sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "sendto$llc(@RSTART@openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)@REND@, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r3 = close(r0)", "r4 = write$unix(r3)"}, 3, []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "r3 = openat$llc(0x35, &(0x7f0000014000)='\\x00'/64, 0x5f, 0x40, 0x0, 0x0)", "sendto$llc(r3, &(0x7f0000014000)='\\x00'/64, 0xb8, 0x40, 0x0, 0x0)", "r4 = close(r0)", "r5 = write$unix(r4)"}},
		{"ResAndPipeAndAlreadyHasPipe", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})", []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})", "r3 = close(r0)", "r4 = write$unix(r3)"}, 3, []string{"r0 = socket()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "r3 = epoll_create1(0x80000)", "epoll_ctl$EPOLL_CTL_ADD(r3, 0x1, r1, &(0x7f000003a000)={0x1, 0x10})", "r4 = close(r0)", "r5 = write$unix(r4)"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseNestedResources(tt.paramCall, tt.paramCalls, tt.paramInsertPosition); !isEqual(got, tt.want) {
				t.Errorf("ParseNestedResources(): \n%v, want \n%v", got, tt.want)
			}
		})
	}
}
