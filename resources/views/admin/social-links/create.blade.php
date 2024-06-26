@extends('admin.layouts.admin')

@section('title', trans('admin.social_links.create'))

@section('content')
    <div class="card shadow mb-4">
        <div class="card-body">
            <form action="{{ route('admin.social-links.store') }}" method="POST" v-scope="{ type: '{{ old('type') }}' }">

                @include('admin.social-links._form')

                <button type="submit" class="btn btn-primary">
                    <i class="bi bi-save"></i> {{ trans('messages.actions.save') }}
                </button>
            </form>
        </div>
    </div>
@endsection
