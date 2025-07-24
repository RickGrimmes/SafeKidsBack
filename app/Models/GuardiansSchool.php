<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class GuardiansSchool extends Model
{
    use HasFactory;

    protected $table = 'guardians_schools';

    protected $fillable = [
        'guardian_id',
        'school_id',
    ];

    public function guardian()
    {
        return $this->belongsTo(Guardians::class, 'guardian_id');
    }

    public function school()
    {
        return $this->belongsTo(Schools::class, 'school_id');
    }
}
