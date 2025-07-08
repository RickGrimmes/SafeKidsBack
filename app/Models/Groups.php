<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Groups extends Model
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
        'schoolId',
        'gradeSection',
    ];

    /**
     * Relación con el estudiante.
     */
    public function student()
    {
        return $this->belongsTo(Students::class, 'studentId');
    }

    /**
     * Relación con la escuela.
     */
    public function school()
    {
        return $this->belongsTo(Schools::class, 'schoolId');
    }
}
