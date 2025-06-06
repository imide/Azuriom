<?php

namespace Azuriom\Models\Traits;

use Azuriom\Models\ActionLog;
use Illuminate\Database\Eloquent\Model;

/**
 * Log actions of this model.
 */
trait Loggable
{
    protected static function bootLoggable(): void
    {
        $events = static::$logEvents ?? ['created', 'updated', 'deleted'];

        foreach ($events as $event) {
            static::$event(function (Model $model) use ($event) {
                $action = str_replace('_', '-', $model->getTable()).'.'.$event;

                $log = ActionLog::log($action, $model, $model->getLogData($event));

                if ($log !== null && $event === 'updated') {
                    $model->createLogEntries($log, $event);
                }
            });
        }
    }

    protected function getLogData(string $event): array
    {
        return [];
    }

    protected function shouldLogAttribute(string $attribute): bool
    {
        if ($attribute === $this->getCreatedAtColumn()
            || $attribute === $this->getUpdatedAtColumn()) {
            return false;
        }

        if (count($this->getVisible()) > 0) {
            return in_array($attribute, $this->getVisible(), true);
        }

        return ! in_array($attribute, $this->getHidden(), true);
    }

    public function createLogEntries(ActionLog $log): void
    {
        foreach ($this->getChanges() as $attribute => $value) {
            $original = $this->getOriginal($attribute);

            if ($this->shouldLogAttribute($attribute) && $this->isValidLogType($original) && $this->isValidLogType($value)) {
                $log->entries()->create([
                    'attribute' => $attribute,
                    'old_value' => $original,
                    'new_value' => $value,
                ]);
            }
        }
    }

    protected function isValidLogType($value): bool
    {
        return $value === null || is_bool($value)
            || is_string($value) || is_numeric($value);
    }
}
