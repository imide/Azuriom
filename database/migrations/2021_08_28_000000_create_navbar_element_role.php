<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('navbar_element_role', function (Blueprint $table) {
            $table->integer('navbar_element_id')->index()->unsigned();
            $table->integer('role_id')->index()->unsigned();

            $table->foreign('navbar_element_id')->references('id')->on('navbar_elements')->cascadeOnDelete();
            $table->foreign('role_id')->references('id')->on('roles')->cascadeOnDelete();

            $table->unique(['navbar_element_id', 'role_id']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('navbar_element_role');
    }
};
