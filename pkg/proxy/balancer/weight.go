package balancer

import (
	"errors"
	"math/rand"
)

type (
	// WeightBalancer balancer
	WeightBalancer struct{}
)

var (
	// ErrZeroWeight is used when there a zero value weight was given
	ErrZeroWeight = errors.New("invalid backend, weight 0 given")
)

// NewWeightBalancer creates a new instance of WeightBalancer
func NewWeightBalancer() *WeightBalancer {
	return &WeightBalancer{}
}

// Elect backend using weight strategy
func (b *WeightBalancer) Elect(hosts []*Target) (*Target, error) {
	if len(hosts) == 0 {
		return nil, ErrEmptyBackendList
	}

	totalWeight := 0
	for _, host := range hosts {
		totalWeight += host.Weight
	}

	if totalWeight <= 0 {
		// if everybody is dead let's try to poke at them at least
		idx := rand.Intn(len(hosts))
		return hosts[idx], nil
	}

	r := rand.Intn(totalWeight)
	pos := 0

	for _, host := range hosts {
		pos += host.Weight
		if r >= pos {
			continue
		}
		return host, nil
	}

	return nil, ErrCannotElectBackend
}
