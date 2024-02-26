package gitlab

import (
	"github.com/goto/guardian/domain"
	"github.com/xanzy/go-gitlab"
)

type pageFetcher[T any] func(gitlab.ListOptions) ([]T, *gitlab.Response, error)

type mapper[T, T2 any] func(T) T2

func fetchAllPages[T any](
	fetchPage pageFetcher[T],
) ([]T, error) {
	var records []T

	opt := gitlab.ListOptions{Page: 1, PerPage: 100}
	for {
		pageRecords, resp, err := fetchPage(opt)
		if err != nil {
			return nil, err
		}
		records = append(records, pageRecords...)

		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		opt.Page = resp.NextPage
	}

	return records, nil
}

func fetchResources[T *gitlab.Group | *gitlab.Project](
	fetchFunc pageFetcher[T],
	mapFunc mapper[T, *domain.Resource],
) ([]*domain.Resource, error) {
	records, err := fetchAllPages(fetchFunc)
	if err != nil {
		return nil, err
	}

	mappedRecords := make([]*domain.Resource, len(records))
	for i, r := range records {
		mappedRecords[i] = mapFunc(r)
	}
	return mappedRecords, nil
}
