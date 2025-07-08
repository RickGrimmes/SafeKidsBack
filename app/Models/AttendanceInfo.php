<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AttendanceInfo extends Model
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
        'studentId',
        'checkIn',
        'checkOut',
        'updatedAt',
        'pickedUpById',
        'pickedUpByType',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'checkIn' => 'datetime',
        'checkOut' => 'datetime',
        'updatedAt' => 'datetime',
        'pickedUpById' => 'integer',
        'pickedUpByType' => 'string',
    ];

    /**
     * Relación con el estudiante.
     */
    public function student()
    {
        return $this->belongsTo(Students::class, 'studentId');
    }
}
