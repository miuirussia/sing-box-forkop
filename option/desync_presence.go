package option

// IsExplicit distinguishes an explicitly configured zero or false from a
// default. NormalizeDesyncOptions retains presence across preset resolution.
func (o DesyncOptions) IsExplicit(key string) bool {
	_, ok := o.present[key]
	return ok
}
