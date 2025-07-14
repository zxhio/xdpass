package utils

import "slices"

func LimitPageSlice[T any](s []T, page, limit int) ([]T, int) {
	return LimitPageSliceFunc(s, page, limit, func(T) bool { return true })
}

func LimitPageSliceFunc[T any](s []T, page, limit int, filter func(T) bool) ([]T, int) {
	// Initialize default values if uest is nil

	// Validate and normalize pagination parameters
	page = max(page, 1)
	limit = max(limit, 1)

	// First pass: count total matches (no allocation)
	total := 0
	if filter != nil {
		for _, item := range s {
			if filter(item) {
				total++
			}
		}
	} else {
		total = len(s)
	}

	data := make([]T, 0, min(limit, total))

	// Early return if no data or page out of range
	if total == 0 || (page-1)*limit >= total {
		return data, total
	}

	// Second pass: collect only needed items
	itemsNeeded := limit
	itemsSkipped := (page - 1) * limit
	currentPos := 0

	for _, item := range s {
		if filter == nil || filter(item) {
			if currentPos >= itemsSkipped && itemsNeeded > 0 {
				data = append(data, item)
				itemsNeeded--
			}
			currentPos++
			if itemsNeeded == 0 {
				break
			}
		}
	}
	return data, total
}

func SliceAppendUnique[S ~[]E, E comparable](s S, v E) S {
	if slices.Contains(s, v) {
		return s
	}
	s = append(s, v)
	return s
}
