<?php

namespace Azuriom\Console\Commands;

use Azuriom\Models\Attachment;
use Azuriom\Models\PendingAttachment;
use Illuminate\Console\Command;

class AttachmentsPurgeCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'attachments:purge';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Purge the unused old attachments.';

    /**
     * Execute the console command.
     *
     * @throws \LogicException
     */
    public function handle()
    {
        $time = now()->subDay();

        $attachments = Attachment::onlyTrashed()
            ->where('deleted_at', '<', $time)
            ->get();

        $count = $attachments->count();

        foreach ($attachments as $attachment) {
            // Ensure the deleted event is fired to delete the file
            $attachment->forceDelete();
        }

        $pendingAttachments = PendingAttachment::where('updated_at', '<', $time)->get();

        $pendingCount = $pendingAttachments->count();

        foreach ($pendingAttachments as $pendingAttachment) {
            // Ensure the deleted event is fired to delete the file
            $pendingAttachment->delete();
        }

        $this->info("{$count} attachments and {$pendingCount} pending attachments was deleted.");
    }
}
