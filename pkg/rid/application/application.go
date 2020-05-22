package application

import (
	"github.com/dpjacques/clockwork"
	"github.com/interuss/dss/pkg/rid/cockroach"
	"github.com/interuss/dss/pkg/rid/repos"
)

// DefaultClock allows stubbing out the clock for a test clock.
var DefaultClock = clockwork.NewRealClock()

// app contains all of the per-entity Applications.
type app struct {
	// TODO: don't fully embed the repos once we reduce the complexity in the store.
	// Right now it's "coincidence" that the repo has the same signatures as the App interface
	// but we will want to simplify the repos and add the complexity here.
	repos.ISA
	repos.Subscription
	clock clockwork.Clock
}

type App interface {
	ISAApp
	SubscriptionApp
}

// NewFromRepo is a convenience function for creating an App
// with the given store.
func NewFromRepo(repo *cockroach.Store) App {
	return &app{
		ISA:          repo.ISA,
		Subscription: repo.Subscription,
		clock:        DefaultClock,
	}
}
