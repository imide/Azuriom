<?php

namespace Azuriom\Models;

use Azuriom\Models\Traits\HasUser;
use Azuriom\Models\Traits\Loggable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\Auth;

/**
 * @property int $id
 * @property int $user_id
 * @property int $author_id
 * @property int|null $remover_id
 * @property string $reason
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 * @property \Carbon\Carbon|null $removed_at
 * @property \Azuriom\Models\User $user
 * @property \Azuriom\Models\User $author
 * @property \Azuriom\Models\User|null $remover
 */
class Ban extends Model
{
    use HasUser;
    use Loggable;
    use SoftDeletes;

    protected const DELETED_AT = 'removed_at';

    /**
     * The actions to that should be automatically logged.
     *
     * @var array<int, string>
     */
    protected static array $logEvents = [
        'created', 'deleted',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_id', 'reason',
    ];

    /**
     * The user key associated with this model.
     */
    protected string $userKey = 'author_id';

    protected static function booted(): void
    {
        foreach (['created', 'deleted'] as $event) {
            static::registerModelEvent($event, function (self $ban) {
                $ban->user->flushBanCache();
            });
        }
    }

    /**
     * Get the banned user.
     */
    public function user()
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get the author of the ban.
     */
    public function author()
    {
        return $this->belongsTo(User::class, 'author_id');
    }

    /**
     * Get the remover of the ban.
     */
    public function remover()
    {
        return $this->belongsTo(User::class, 'remover_id');
    }

    /**
     * Remove this ban.
     *
     * @throws \LogicException
     */
    public function removeBan(?User $remover = null): void
    {
        $this->remover()->associate($remover ?? Auth::user());
        $this->save();

        $this->delete();
    }
}
