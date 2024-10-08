<?php

namespace Azuriom\Models\Traits;

use Azuriom\Models\Attachment;
use Azuriom\Models\PendingAttachment;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Str;

/**
 * Associate multiple attachments to a model.
 *
 * @property \Illuminate\Support\Collection|\Azuriom\Models\Attachment[] $attachments
 */
trait Attachable
{
    public static function bootAttachable(): void
    {
        static::updated(function (self $model) {
            $content = $model->getAttribute($model->getAttachmentsKey());

            if ($model->getOriginal($model->getAttachmentsKey()) === $content) {
                return;
            }

            $attachments = $model->attachments()->withTrashed()->get();

            foreach ($attachments as $attachment) {
                if (Str::contains($content, $attachment->file)) {
                    if ($attachment->trashed()) {
                        $attachment->restore();
                    }
                } elseif (! $attachment->trashed()) {
                    $attachment->delete();
                }
            }
        });

        static::deleted(function (self $model) {
            $attachments = $model->attachments()->withTrashed()->get();

            foreach ($attachments as $attachment) {
                $attachment->setRelation('attachable', $model)->forceDelete();
            }
        });
    }

    public static function storePendingAttachment(string $pendingId, UploadedFile $file): string
    {
        $attachment = new PendingAttachment([
            'pending_id' => $pendingId,
            'pending_type' => (new self())->getAttachmentsType(),
        ]);

        return $attachment->storeImage($file, true);
    }

    public function persistPendingAttachments(?string $pendingId): void
    {
        if ($pendingId === null) {
            return;
        }

        $attachments = PendingAttachment::where('pending_id', $pendingId)
            ->where('pending_type', $this->getAttachmentsType())
            ->get();

        $content = $this->getAttribute($this->getAttachmentsKey());

        foreach ($attachments as $attachment) {
            if (Str::contains($content, $attachment->file)) {
                $this->attachments()
                    ->make()
                    ->forceFill(['file' => $attachment->file])
                    ->save();

                // We don't want to delete the file since now a permanent attachment use it
                $attachment->forceFill(['file' => null]);
            }

            // Delete the pending attachment, and the file if it was not used
            $attachment->delete();
        }
    }

    public function storeAttachment(UploadedFile $file): string
    {
        /** @var \Azuriom\Models\Attachment $attachment */
        $attachment = $this->attachments()->make();

        return $attachment->storeImage($file, true);
    }

    public function attachments()
    {
        return $this->morphMany(Attachment::class, 'attachable');
    }

    public function getAttachmentsKey(): string
    {
        return 'content';
    }

    public function getAttachmentsType(): string
    {
        return (new self())->getMorphClass();
    }

    public function getAttachmentsPath(): string
    {
        return Str::replace('_', '/', $this->getTable()).'/attachments';
    }
}
