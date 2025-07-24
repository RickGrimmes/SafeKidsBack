<?php

namespace App\Models;

use App\Models\SchoolUsers;
use App\Models\SchoolTypes;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Schools extends Model
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
        'name',
        'address',
        'phone',
        'city',
        'status',
        'created_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'status' => 'boolean',
        'created_at' => 'datetime',
    ];

    public function schoolUsers()
    {
        return $this->hasMany(SchoolUsers::class, 'schoolId');
    }

    public function schoolTypes()
    {
        return $this->hasMany(SchoolTypes::class, 'schoolId');
    }
}
