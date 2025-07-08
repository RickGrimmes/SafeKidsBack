<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class UserRole extends Model
{
    use HasFactory;

    /**
     * Indicates if the model should be timestamped.
     */
    public $timestamps = false;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'userId',
        'roleId',
        'status',
        'createdBy',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'status' => 'boolean',
    ];

    /**
     * Get the user that owns this role assignment.
     */
    public function user()
    {
        return $this->belongsTo(User::class, 'userId');
    }

    /**
     * Get the role assigned.
     */
    public function role()
    {
        return $this->belongsTo(Role::class, 'roleId');
    }

    /**
     * Get the user who created this assignment.
     */
    public function creator()
    {
        return $this->belongsTo(User::class, 'createdBy');
    }
}
