package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueryWithPage(t *testing.T) {
	testCases := []struct {
		data   []*int
		page   int
		limit  int
		filter func(*int) bool
		result []*int
	}{
		{
			data:   slicesPtr([]int{1, 2, 3}),
			result: slicesPtr([]int{1, 2, 3}),
		},
		{
			data: slicesPtr([]int{1, 2, 3}),
			page: 1, limit: 10,
			result: slicesPtr([]int{1, 2, 3}),
		},
		{
			data: slicesPtr([]int{1, 2, 3}),
			page: 1, limit: 2,
			result: slicesPtr([]int{1, 2}),
		},
		{
			data: slicesPtr([]int{1, 2, 3}),
			page: 2, limit: 2,
			result: slicesPtr([]int{3}),
		},
		{
			data: slicesPtr([]int{1, 2, 3, 4, 5}),
			page: 1, limit: 2,
			result: slicesPtr([]int{1, 3}),
			filter: func(i *int) bool { return *i%2 == 1 },
		},
		{
			data: slicesPtr([]int{1, 2, 3, 4, 5}),
			page: 2, limit: 2,
			result: slicesPtr([]int{5}),
			filter: func(i *int) bool { return *i%2 == 1 },
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d_%d_%d_%d", len(tc.data), tc.page, tc.limit, len(tc.result)), func(t *testing.T) {
			resp := QueryWithPage(tc.data, &QueryPage{Page: tc.page, Limit: tc.limit}, tc.filter)
			assert.Equal(t, resp.Data, tc.result)
		})
	}
}

func v2p[T any](v T) *T {
	return &v
}

func slicesPtr[T any](s []T) []*T {
	sp := make([]*T, 0, len(s))
	for _, v := range s {
		sp = append(sp, v2p(v))
	}
	return sp
}
