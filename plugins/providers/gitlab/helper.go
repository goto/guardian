package gitlab

import (
	"context"

	"github.com/goto/guardian/domain"
	"github.com/xanzy/go-gitlab"
)

type pageFetcher[T any] func(gitlab.ListOptions, ...gitlab.RequestOptionFunc) ([]T, *gitlab.Response, error)

type mapper[T, T2 any] func(T) T2

func fetchAllPages[T any](
	ctx context.Context,
	fetchPage pageFetcher[T],
) ([]T, error) {
	var records []T

	opt := gitlab.ListOptions{
		PerPage:    100,
		Pagination: "keyset",
		OrderBy:    "id",
		Sort:       "asc",
	}
	options := []gitlab.RequestOptionFunc{gitlab.WithContext(ctx)}
	for {
		pageRecords, resp, err := fetchPage(opt, options...)
		if err != nil {
			return nil, err
		}
		records = append(records, pageRecords...)

		if resp.NextLink == "" {
			break
		}
		opt.Page = resp.NextPage
		options = []gitlab.RequestOptionFunc{
			gitlab.WithContext(ctx),
			gitlab.WithKeysetPaginationParameters(resp.NextLink),
		}
	}

	return records, nil
}

func fetchResources[T *gitlab.Group | *gitlab.Project](
	ctx context.Context,
	fetchFunc pageFetcher[T],
	mapFunc mapper[T, *domain.Resource],
) ([]*domain.Resource, error) {
	records, err := fetchAllPages(ctx, fetchFunc)
	if err != nil {
		return nil, err
	}

	mappedRecords := make([]*domain.Resource, len(records))
	for i, r := range records {
		mappedRecords[i] = mapFunc(r)
	}
	return mappedRecords, nil
}
