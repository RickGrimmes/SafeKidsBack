<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class SchoolUsers extends Model
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
        'schoolId',
        'userRoleId',
    ];

    /**
     * Relación con la escuela.
     */
    public function school()
    {
        return $this->belongsTo(Schools::class, 'schoolId');
    }

    /**
     * Relación con el userRole.
     */
    public function userRole()
    {
        return $this->belongsTo(UserRole::class, 'userRoleId');
    }
}
