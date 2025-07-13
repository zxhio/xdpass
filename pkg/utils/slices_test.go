package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLimitPageSlice(t *testing.T) {
	testCases := []struct {
		data   []int
		page   int
		limit  int
		filter func(int) bool
		result []int
	}{
		{
			data:   []int{1, 2, 3},
			result: []int{1},
		},
		{
			data: []int{1, 2, 3},
			page: 1, limit: 10,
			result: []int{1, 2, 3},
		},
		{
			data: []int{1, 2, 3},
			page: 1, limit: 2,
			result: []int{1, 2},
		},
		{
			data: []int{1, 2, 3},
			page: 2, limit: 2,
			result: []int{3},
		},
		{
			data: []int{1, 2, 3, 4, 5},
			page: 1, limit: 2,
			result: []int{1, 3},
			filter: func(i int) bool { return i%2 == 1 },
		},
		{
			data: []int{1, 2, 3, 4, 5},
			page: 2, limit: 2,
			result: []int{5},
			filter: func(i int) bool { return i%2 == 1 },
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d_%d_%d_%d", len(tc.data), tc.page, tc.limit, len(tc.result)), func(t *testing.T) {
			data, _ := LimitPageSliceFunc(tc.data, tc.page, tc.limit, tc.filter)
			assert.Equal(t, tc.result, data)
		})
	}
}
