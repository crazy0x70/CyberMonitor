package history

import (
	"context"
	"math"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

const (
	allSeriesMint = math.MinInt64
	allSeriesMaxt = math.MaxInt64
)

type seriesQuerier interface {
	Querier(mint, maxt int64) (storage.Querier, error)
}

func hasMatchingSeries(db seriesQuerier, matchers ...*labels.Matcher) (bool, error) {
	if db == nil {
		return false, nil
	}
	querier, err := db.Querier(allSeriesMint, allSeriesMaxt)
	if err != nil {
		return false, err
	}
	defer querier.Close()

	seriesSet := querier.Select(context.Background(), false, &storage.SelectHints{
		Start: allSeriesMint,
		End:   allSeriesMaxt,
	}, matchers...)
	for seriesSet.Next() {
		iterator := seriesSet.At().Iterator(nil)
		for valueType := iterator.Next(); valueType != chunkenc.ValNone; valueType = iterator.Next() {
			if valueType == chunkenc.ValFloat {
				return true, nil
			}
		}
		if err := iterator.Err(); err != nil {
			return false, err
		}
	}
	if err := seriesSet.Err(); err != nil {
		return false, err
	}
	return false, nil
}
