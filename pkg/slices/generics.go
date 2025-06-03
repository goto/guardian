package slices

import (
	originSlices "slices"

	"golang.org/x/exp/constraints"
)

func GenericsFilterSliceEmptyValues[T comparable](list []T) []T {
	result := make([]T, 0)
	var emptyValue T
	for _, v := range list {
		// if T value is empty (ex: "", 0, false)
		if v == emptyValue {
			continue
		}
		result = append(result, v)
	}
	return result
}

func GenericsUniqueSliceValues[T comparable](list []T) []T {
	result := make([]T, 0)
	seen := make(map[T]struct{})
	for _, v := range list {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

func GenericsIsSliceEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[T]int)
	for _, v := range a {
		counts[v]++
	}
	for _, v := range b {
		counts[v]--
		if counts[v] < 0 {
			return false
		}
	}
	return true
}

func GenericsStandardizeSlice[T constraints.Ordered](list []T) []T {
	if list == nil {
		list = make([]T, 0)
		return list
	}
	result := GenericsFilterSliceEmptyValues(list)
	result = GenericsUniqueSliceValues(result)
	originSlices.Sort(result)
	return result
}

func GenericsSliceContainsAll[T constraints.Ordered](list []T, in ...T) bool {
	if len(list) == 0 || len(in) == 0 {
		return false
	}
	for _, v := range in {
		if !originSlices.Contains(list, v) {
			return false
		}
	}
	return true
}

func GenericsSliceContainsOne[T constraints.Ordered](list []T, in ...T) bool {
	if len(list) == 0 || len(in) == 0 {
		return false
	}
	for _, v := range in {
		if originSlices.Contains(list, v) {
			return true
		}
	}
	return false
}
