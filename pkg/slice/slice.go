package slice

// DeleteElement removes the element at the provided position.
// This destroyes the order but avoids excessive moves
func DeleteElement[T any](s []T, i int) []T {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

// Reverse reverses the elements of a slice.
// This is different from sort.Reverse as that reverses based on order.
// This reverses based on position only.
func Reverse[T any](s []T) []T {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}
