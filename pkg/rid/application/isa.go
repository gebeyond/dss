package application

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/geo/s2"
	dsserr "github.com/interuss/dss/pkg/errors"
	"github.com/interuss/dss/pkg/geo"
	dssmodels "github.com/interuss/dss/pkg/models"
	ridmodels "github.com/interuss/dss/pkg/rid/models"
)

// AppInterface provides the interface to the application logic for ISA entities
// Note that there is no need for the applciation layer to have the same API as
// the repo layer.
type ISAApp interface {
	GetISA(ctx context.Context, id dssmodels.ID) (*ridmodels.IdentificationServiceArea, error)

	// DeleteISA deletes the IdentificationServiceArea identified by "id" and owned by "owner".
	// Returns the delete IdentificationServiceArea and all Subscriptions affected by the delete.
	DeleteISA(ctx context.Context, id dssmodels.ID, owner dssmodels.Owner, version *dssmodels.Version) (*ridmodels.IdentificationServiceArea, []*ridmodels.Subscription, error)

	// InsertISA inserts or updates an ISA.
	InsertISA(ctx context.Context, isa *ridmodels.IdentificationServiceArea) (*ridmodels.IdentificationServiceArea, []*ridmodels.Subscription, error)

	// UpdateISA
	UpdateISA(ctx context.Context, isa *ridmodels.IdentificationServiceArea) (*ridmodels.IdentificationServiceArea, []*ridmodels.Subscription, error)

	// SearchISAs returns all subscriptions ownded by "owner" in "cells".
	SearchISAs(ctx context.Context, cells s2.CellUnion, earliest *time.Time, latest *time.Time) ([]*ridmodels.IdentificationServiceArea, error)
}

// SearchISAs for ISA within the volume bounds.
func (a *app) SearchISAs(ctx context.Context, cells s2.CellUnion, earliest *time.Time, latest *time.Time) ([]*ridmodels.IdentificationServiceArea, error) {
	now := a.clock.Now()
	if earliest == nil || earliest.Before(now) {
		earliest = &now
	}

	return a.Repository.SearchISAs(ctx, cells, earliest, latest)
}

// DeleteISA the given ISA
func (a *app) DeleteISA(ctx context.Context, id dssmodels.ID, owner dssmodels.Owner, version *dssmodels.Version) (*ridmodels.IdentificationServiceArea, []*ridmodels.Subscription, error) {
	var (
		ret  *ridmodels.IdentificationServiceArea
		subs []*ridmodels.Subscription
	)
	// The following will automatically retry TXN retry errors.
	err := a.Repository.InTxnRetrier(ctx, func(ctx context.Context) error {
		old, err := a.Repository.GetISA(ctx, id)
		switch {
		case err != nil:
			return err
		case old == nil:
			return dsserr.NotFound(id.String())
		case !version.Matches(old.Version):
			return dsserr.VersionMismatch(fmt.Sprintf("old version for isa %s", id))
		case old.Owner != owner:
			return dsserr.PermissionDenied(fmt.Sprintf("ISA is owned by %s", old.Owner))
		}

		ret, err = a.Repository.DeleteISA(ctx, old)
		if err != nil {
			return err
		}

		subs, err = a.Repository.UpdateNotificationIdxsInCells(ctx, old.Cells)
		return err
	})
	return ret, subs, err
}

// InsertISA implments the AppInterface InsertISA method
func (a *app) InsertISA(ctx context.Context, isa *ridmodels.IdentificationServiceArea) (*ridmodels.IdentificationServiceArea, []*ridmodels.Subscription, error) {
	// Validate and perhaps correct StartTime and EndTime.
	if err := isa.AdjustTimeRange(a.clock.Now(), nil); err != nil {
		return nil, nil, err
	}
	// Update the notification index for both cells removed and added.
	var (
		ret  *ridmodels.IdentificationServiceArea
		subs []*ridmodels.Subscription
	)
	// The following will automatically retry TXN retry errors.
	err := a.Repository.InTxnRetrier(ctx, func(ctx context.Context) error {
		// ensure it doesn't exist yet
		old, err := a.Repository.GetISA(ctx, isa.ID)
		if err != nil {
			return err
		}
		if old != nil {
			return dsserr.AlreadyExists(fmt.Sprintf("isa with id: %s already exists", isa.ID))
		}

		// UpdateNotificationIdxsInCells is done in a Txn along with insert since
		// they are both modifying the db. Insert a susbcription alone does
		// not do this, so that does not need to use a txn (in subscription.go).
		subs, err = a.Repository.UpdateNotificationIdxsInCells(ctx, isa.Cells)
		if err != nil {
			return err
		}
		ret, err = a.Repository.InsertISA(ctx, isa)
		return err
	})
	return ret, subs, err
}

// UpdateISA implments the AppInterface UpdateISA method
func (a *app) UpdateISA(ctx context.Context, isa *ridmodels.IdentificationServiceArea) (*ridmodels.IdentificationServiceArea, []*ridmodels.Subscription, error) {
	// Update the notification index for both cells removed and added.
	var (
		ret  *ridmodels.IdentificationServiceArea
		subs []*ridmodels.Subscription
	)
	// The following will automatically retry TXN retry errors.
	err := a.Repository.InTxnRetrier(ctx, func(ctx context.Context) error {
		var err error

		old, err := a.Repository.GetISA(ctx, isa.ID)
		switch {
		case err != nil:
			return err
		case old == nil:
			return dsserr.NotFound(fmt.Sprintf("isa not found: %s", isa.ID))
		case old.Owner != isa.Owner:
			return dsserr.PermissionDenied(fmt.Sprintf("ISA is owned by %s", old.Owner))
		case !old.Version.Matches(isa.Version):
			return dsserr.VersionMismatch(fmt.Sprintf("old version for isa: %s", isa.ID))
		}
		// Validate and perhaps correct StartTime and EndTime.
		if err := isa.AdjustTimeRange(a.clock.Now(), old); err != nil {
			return err
		}

		ret, err = a.Repository.UpdateISA(ctx, isa)
		if err != nil {
			return err
		}

		// TODO steeling, we should change this to a Custom type, to obfuscate
		// some of these metrics and prevent us from doing the wrong thing.
		cells := s2.CellUnionFromUnion(old.Cells, isa.Cells)
		geo.Levelify(&cells)
		// UpdateNotificationIdxsInCells is done in a Txn along with insert since
		// they are both modifying the db. Insert a susbcription alone does
		// not do this, so that does not need to use a txn (in subscription.go).
		subs, err = a.Repository.UpdateNotificationIdxsInCells(ctx, cells)
		return err
	})

	return ret, subs, err
}
