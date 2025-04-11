package prog

import (
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
		want bool
	}{
		{"HasResource", "r0 = sendto$llc()", true},
		{"NoResource", "poll(@RSTART@sendto$llc()@REND@)", false},
		{"NonResourceStart", "recvfrom$unix()", false},
		{"EmptyString", "", false},
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
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "read(r1, &(0x7f0000055000)=\"\"/0x400, 0xa)", "r4 = close(r0)", "r5 = write$unix(r4)"},
		},
		{
			"EpollOnePipe",
			"epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})",
			[]string{"r0 = openat()", "read(r0)", "epoll_ctl$EPOLL_CTL_ADD(@RSTART@epoll_create1(0x80000)@REND@, 0x1, @PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@, &(0x7f000003a000)={0x1, 0x10})", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "r1 = epoll_create1(0x80000)", "pipe(&(0x7f0000064000)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})", "epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, &(0x7f000003a000)={0x1, 0x10})", "r4 = close(r0)", "r5 = write$unix(r4)"},
		},
		{
			"PollTwoPipes",
			"poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@ }, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@ }], 0x2, 0x3e0)",
			[]string{"r0 = openat()", "read(r0)", "poll(&(0x7f0000080000)=[{@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@ }, {@PIPESTART@pipe(&(0x7f0000064000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})@PIPEEND@ }], 0x2, 0x3e0)", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f0000064000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "poll(&(0x7f0000080000)=[{r1 }, {r2 }], 0x2, 0x3e0)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
		{
			"SpliceTwoPipes",
			"splice$SyzLLM(@PIPESTART@pipe(&(0x7f00000d7000)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e2000)=nil, @PIPESTART@pipe(&(0x7f00000d7000)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e6000)=nil, 0x10000, 0x5)",
			[]string{"r0 = openat()", "read(r0)", "splice$SyzLLM(@PIPESTART@pipe(&(0x7f00000d7000)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e2000)=nil, @PIPESTART@pipe(&(0x7f00000d7000)={<r2=>0xffffffffffffffff, <r3=>0xffffffffffffffff})@PIPEEND@, &(0x7f00000e6000)=nil, 0x10000, 0x5)", "r1 = close(r0)", "r2 = write$unix(r1)"},
			2,
			[]string{"r0 = openat()", "read(r0)", "pipe(&(0x7f00000d7000)={<r1=>0xffffffffffffffff, <r2=>0xffffffffffffffff})", "splice$SyzLLM(r1, &(0x7f00000e2000)=nil, r2, &(0x7f00000e6000)=nil, 0x10000, 0x5)", "r3 = close(r0)", "r4 = write$unix(r3)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePipeResource(tt.paramCall, tt.paramCalls, tt.paramInsertPosition, 0); !isEqual(got, tt.want) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseNestedResources(tt.paramCall, tt.paramCalls, tt.paramInsertPosition); !isEqual(got, tt.want) {
				t.Errorf("ParseNestedResources(): \n%v, want \n%v", got, tt.want)
			}
		})
	}
}
