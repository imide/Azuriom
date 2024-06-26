<?php

namespace Azuriom\Models\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;

/**
 * Add a simple search method to a model.
 *
 * @method static \Illuminate\Database\Eloquent\Builder search(string $search, array|string|null $columns = null)
 */
trait Searchable
{
    /**
     * Scope a query to only include results that match the search.
     */
    public function scopeSearch(Builder $query, string $search, array|string|null $columns = null): void
    {
        $columns = $columns !== null ? Arr::wrap($columns) : $this->searchable;

        if ($columns === ['*']) {
            $columns = $this->searchable;
        }

        $query->where(fn ($query) => $this->runSearch($query, $search, $columns));
    }

    protected function runSearch(Builder $query, string $search, array $columns): void
    {
        $models = [];

        foreach ($columns as $column) {
            if (Str::contains($column, '.')) {
                [$model, $column] = explode('.', $column);

                $models[$model] = [...$models[$model] ?? [], $column];
            } else {
                $query->orWhere($column, 'like', "%{$search}%");
            }
        }

        foreach ($models as $model => $column) {
            $query->orWhereRelation($model, function (Builder $query) use ($column, $search) {
                $query->search($search, $column);
            });
        }

        if (is_numeric($search) || $this->getKeyType() !== 'int') {
            $query->orWhere($this->getKeyName(), $search);
        }
    }
}
