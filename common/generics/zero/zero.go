package zero

func GetZero[T any]() T {
	var result T
	return result
}

func IsZero[T any](a T) bool {
	// be careful, compare by interface{} maybe cause panic if the dynamic value can't be compared (eg: map,slice,function).
	return any(a) == any(GetZero[T]())
}
