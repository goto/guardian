package slices_test

import (
	"testing"

	"github.com/goto/guardian/pkg/slices"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/constraints"
)

func TestGenericsFilterSliceEmptyValues(t *testing.T) {
	type args[T comparable] struct {
		list []T
	}
	type testCase[T comparable] struct {
		name string
		args args[T]
		want []T
	}
	testsString := []testCase[string]{
		{
			name: "type string",
			args: args[string]{[]string{"a", "b", "", "c", "", "", "d", "e", "", "", "", "f"}},
			want: []string{"a", "b", "c", "d", "e", "f"},
		},
	}
	for _, tt := range testsString {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsFilterSliceEmptyValues(tt.args.list), "GenericsFilterSliceEmptyValues(%v)", tt.args.list)
		})
	}
	testsInt := []testCase[int]{
		{
			name: "type int",
			args: args[int]{[]int{1, 2, 0, 3, 0, 0, 4, 5, 0, 0, 0, 6}},
			want: []int{1, 2, 3, 4, 5, 6},
		},
	}
	for _, tt := range testsInt {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsFilterSliceEmptyValues(tt.args.list), "GenericsFilterSliceEmptyValues(%v)", tt.args.list)
		})
	}
	testsBool := []testCase[bool]{
		{
			name: "type bool",
			args: args[bool]{[]bool{true, true, false, false, true}},
			want: []bool{true, true, true},
		},
	}
	for _, tt := range testsBool {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsFilterSliceEmptyValues(tt.args.list), "GenericsFilterSliceEmptyValues(%v)", tt.args.list)
		})
	}
}

func TestGenericsUniqueSliceValues(t *testing.T) {
	type args[T comparable] struct {
		list []T
	}
	type testCase[T comparable] struct {
		name string
		args args[T]
		want []T
	}
	testsString := []testCase[string]{
		{
			name: "type string nil",
			args: args[string]{nil},
			want: []string{},
		},
		{
			name: "type string",
			args: args[string]{[]string{"orange", "orange", "grape", "mellon", "apple", "apple", "orange"}},
			want: []string{"orange", "grape", "mellon", "apple"},
		},
	}
	for _, tt := range testsString {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsUniqueSliceValues(tt.args.list), "GenericsUniqueSliceValues(%v)", tt.args.list)
		})
	}
	testsInt := []testCase[int]{
		{
			name: "type int",
			args: args[int]{[]int{1, 1, 2, 2, 0, 0, 3, 3, 4, 5, 6}},
			want: []int{1, 2, 0, 3, 4, 5, 6},
		},
	}
	for _, tt := range testsInt {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsUniqueSliceValues(tt.args.list), "GenericsUniqueSliceValues(%v)", tt.args.list)
		})
	}
	testsBool := []testCase[bool]{
		{
			name: "type bool",
			args: args[bool]{[]bool{true, true, false, false, true}},
			want: []bool{true, false},
		},
	}
	for _, tt := range testsBool {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsUniqueSliceValues(tt.args.list), "GenericsUniqueSliceValues(%v)", tt.args.list)
		})
	}
}

func TestGenericsIsSliceEqual(t *testing.T) {
	type args[T comparable] struct {
		a []T
		b []T
	}
	type testCase[T comparable] struct {
		name string
		args args[T]
		want bool
	}
	testsString := []testCase[string]{
		{
			name: "type string nil",
			args: args[string]{
				a: nil,
				b: nil,
			},
			want: true,
		},
		{
			name: "type string equal",
			args: args[string]{
				a: []string{"orange", "orange", "grape", "mellon", "apple", "apple", "orange"},
				b: []string{"orange", "apple", "apple", "orange", "grape", "mellon", "orange"},
			},
			want: true,
		},
		{
			name: "type string not equal",
			args: args[string]{
				a: []string{"orange", "orange", "grape", "mellon", "apple", "apple", "orange"},
				b: []string{"orange", "grape", "apple", "orange", "grape", "mellon", "mellon"},
			},
			want: false,
		},
		{
			name: "type string not equal 2",
			args: args[string]{
				a: []string{"orange"},
				b: []string{"orange", "apple"},
			},
			want: false,
		},
		{
			name: "type string not equal 3",
			args: args[string]{
				a: []string{"orange", "apple"},
				b: []string{"orange"},
			},
			want: false,
		},
	}
	for _, tt := range testsString {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsIsSliceEqual(tt.args.a, tt.args.b), "GenericsIsSliceEqual(%v, %v)", tt.args.a, tt.args.b)
		})
	}
	testsInt := []testCase[int]{
		{
			name: "type int nil",
			args: args[int]{
				a: nil,
				b: nil,
			},
			want: true,
		},
		{
			name: "type int equal",
			args: args[int]{
				a: []int{1, 2, 3, 4, 5, 5, 6},
				b: []int{6, 5, 5, 4, 3, 2, 1},
			},
			want: true,
		},
		{
			name: "type int not equal",
			args: args[int]{
				a: []int{1, 2, 3, 4, 5, 6},
				b: []int{1, 2, 3, 4, 5, 7},
			},
			want: false,
		},
		{
			name: "type int not equal 2",
			args: args[int]{
				a: []int{1},
				b: []int{1, 2},
			},
			want: false,
		},
		{
			name: "type int not equal 3",
			args: args[int]{
				a: []int{1, 2},
				b: []int{1},
			},
			want: false,
		},
	}
	for _, tt := range testsInt {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsIsSliceEqual(tt.args.a, tt.args.b), "GenericsIsSliceEqual(%v, %v)", tt.args.a, tt.args.b)
		})
	}
	testsBool := []testCase[bool]{
		{
			name: "type bool nil",
			args: args[bool]{
				a: nil,
				b: nil,
			},
			want: true,
		},
		{
			name: "type bool equal",
			args: args[bool]{
				a: []bool{true, false, true, false},
				b: []bool{false, true, false, true},
			},
			want: true,
		},
		{
			name: "type bool not equal",
			args: args[bool]{
				a: []bool{true, true, false, false},
				b: []bool{true, false, false, false},
			},
			want: false,
		},
		{
			name: "type bool not equal 2",
			args: args[bool]{
				a: []bool{true},
				b: []bool{true, false},
			},
			want: false,
		},
		{
			name: "type bool not equal 3",
			args: args[bool]{
				a: []bool{true, false},
				b: []bool{true},
			},
			want: false,
		},
	}
	for _, tt := range testsBool {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsIsSliceEqual(tt.args.a, tt.args.b), "GenericsIsSliceEqual(%v, %v)", tt.args.a, tt.args.b)
		})
	}
}

func TestGenericsStandardizeSlice(t *testing.T) {
	type args[T constraints.Ordered] struct {
		list []T
	}
	type testCase[T constraints.Ordered] struct {
		name string
		args args[T]
		want []T
	}
	testsString := []testCase[string]{
		{
			name: "type string nil",
			args: args[string]{nil},
			want: []string{},
		},
		{
			name: "type string with duplicates and empty values",
			args: args[string]{[]string{"apple", "", "banana", "apple", "cherry", ""}},
			want: []string{"apple", "banana", "cherry"},
		},
		{
			name: "type string with only empty values",
			args: args[string]{[]string{"", "", ""}},
			want: []string{},
		},
		{
			name: "type string already unique and sorted",
			args: args[string]{[]string{"apple", "banana", "cherry"}},
			want: []string{"apple", "banana", "cherry"},
		},
		{
			name: "type string mixed values",
			args: args[string]{[]string{"banana", "apple", "orange", "banana", "", "grape", "apple", ""}},
			want: []string{"apple", "banana", "grape", "orange"},
		},
	}
	for _, tt := range testsString {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsStandardizeSlice(tt.args.list), "GenericsStandardizeSlice(%v)", tt.args.list)
		})
	}
	testsInt := []testCase[int]{
		{
			name: "type int nil",
			args: args[int]{nil},
			want: []int{},
		},
		{
			name: "type int with duplicates and zeros",
			args: args[int]{[]int{3, 1, 2, 0, 3, 0, 1, 2}},
			want: []int{1, 2, 3},
		},
		{
			name: "type int with only zeros",
			args: args[int]{[]int{0, 0, 0, 0}},
			want: []int{},
		},
		{
			name: "type int already unique and sorted",
			args: args[int]{[]int{1, 2, 3, 4, 5}},
			want: []int{1, 2, 3, 4, 5},
		},
		{
			name: "type int mixed values",
			args: args[int]{[]int{5, 3, 0, 2, 3, 5, 1, 4, 0, 2}},
			want: []int{1, 2, 3, 4, 5},
		},
	}
	for _, tt := range testsInt {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsStandardizeSlice(tt.args.list), "GenericsStandardizeSlice(%v)", tt.args.list)
		})
	}
}

func TestGenericsSliceContainsAll(t *testing.T) {
	type args[T constraints.Ordered] struct {
		list []T
		in   []T
	}
	type testCase[T constraints.Ordered] struct {
		name string
		args args[T]
		want bool
	}
	testsString := []testCase[string]{
		{
			name: "type string nil",
			args: args[string]{nil, nil},
			want: false,
		},
		{
			name: "type string empty params",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{}},
			want: false,
		},
		{
			name: "type string contain",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry"}},
			want: true,
		},
		{
			name: "type string contains",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry", "apple"}},
			want: true,
		},
		{
			name: "type string not contain",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"invalid"}},
			want: false,
		},
		{
			name: "type string not contains",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"invalid-1", "invalid-2"}},
			want: false,
		},
		{
			name: "type string contains & not contain",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry", "apple", "invalid"}},
			want: false,
		},
		{
			name: "type string contains & not contains",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry", "apple", "invalid-1", "invalid-2"}},
			want: false,
		},
	}
	for _, tt := range testsString {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsSliceContainsAll(tt.args.list, tt.args.in...), "GenericsSliceContainsAll(%v, %v)", tt.args.list, tt.args.in)
		})
	}
	testsInt := []testCase[int]{
		{
			name: "type int nil",
			args: args[int]{nil, nil},
			want: false,
		},
		{
			name: "type int empty params",
			args: args[int]{[]int{1, 2, 3, 0}, []int{}},
			want: false,
		},
		{
			name: "type int contain",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3}},
			want: true,
		},
		{
			name: "type int contains",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3, 0}},
			want: true,
		},
		{
			name: "type int not contain",
			args: args[int]{[]int{1, 2, 3, 0}, []int{9}},
			want: false,
		},
		{
			name: "type int not contains",
			args: args[int]{[]int{1, 2, 3, 0}, []int{9, 10}},
			want: false,
		},
		{
			name: "type int contains & not contain",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3, 0, 9}},
			want: false,
		},
		{
			name: "type int contains & not contains",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3, 0, 9, 10}},
			want: false,
		},
	}
	for _, tt := range testsInt {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsSliceContainsAll(tt.args.list, tt.args.in...), "GenericsSliceContainsAll(%v, %v)", tt.args.list, tt.args.in)
		})
	}
}

func TestGenericsSliceContainsOne(t *testing.T) {
	type args[T constraints.Ordered] struct {
		list []T
		in   []T
	}
	type testCase[T constraints.Ordered] struct {
		name string
		args args[T]
		want bool
	}
	testsString := []testCase[string]{
		{
			name: "type string nil",
			args: args[string]{nil, nil},
			want: false,
		},
		{
			name: "type string empty params",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{}},
			want: false,
		},
		{
			name: "type string contain",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry"}},
			want: true,
		},
		{
			name: "type string contains",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry", "apple"}},
			want: true,
		},
		{
			name: "type string not contain",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"invalid"}},
			want: false,
		},
		{
			name: "type string not contains",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"invalid-1", "invalid-2"}},
			want: false,
		},
		{
			name: "type string contains & not contain",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry", "apple", "invalid"}},
			want: true,
		},
		{
			name: "type string contains & not contains",
			args: args[string]{[]string{"apple", "banana", "apple", "cherry"}, []string{"cherry", "apple", "invalid-1", "invalid-2"}},
			want: true,
		},
	}
	for _, tt := range testsString {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsSliceContainsOne(tt.args.list, tt.args.in...), "GenericsSliceContainsOne(%v, %v)", tt.args.list, tt.args.in)
		})
	}
	testsInt := []testCase[int]{
		{
			name: "type int nil",
			args: args[int]{nil, nil},
			want: false,
		},
		{
			name: "type int empty params",
			args: args[int]{[]int{1, 2, 3, 0}, []int{}},
			want: false,
		},
		{
			name: "type int contain",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3}},
			want: true,
		},
		{
			name: "type int contains",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3, 0}},
			want: true,
		},
		{
			name: "type int not contain",
			args: args[int]{[]int{1, 2, 3, 0}, []int{9}},
			want: false,
		},
		{
			name: "type int not contains",
			args: args[int]{[]int{1, 2, 3, 0}, []int{9, 10}},
			want: false,
		},
		{
			name: "type int contains & not contain",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3, 0, 9}},
			want: true,
		},
		{
			name: "type int contains & not contains",
			args: args[int]{[]int{1, 2, 3, 0}, []int{3, 0, 9, 10}},
			want: true,
		},
	}
	for _, tt := range testsInt {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, slices.GenericsSliceContainsOne(tt.args.list, tt.args.in...), "GenericsSliceContainsOne(%v, %v)", tt.args.list, tt.args.in)
		})
	}
}
