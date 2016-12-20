<div class="form-group col-md-12">

    <label>{{ $field['label'] }}</label>
        <br>
        <img src="{{$field['value']}}" height="250px">
        <input type="file" name="{{$field['name']}}" class="form-control">




        {{-- ########################################## --}}
        {{-- Extra CSS and JS for this particular field --}}
        {{-- If a field type is shown multiple times on a form, the CSS and JS will only be loaded once --}}
@if ($crud->checkIfFieldIsFirstOfItsType($field, $fields))

    {{-- FIELD CSS - will be loaded in the after_styles section --}}
    @push('crud_fields_styles')
    {{-- YOUR CSS HERE --}}
    @endpush

    {{-- FIELD JS - will be loaded in the after_scripts section --}}
    @push('crud_fields_scripts')
    {{-- YOUR JS HERE --}}
    @endpush

@endif
{{-- End of Extra CSS and JS --}}
{{-- ########################################## --}}

</div>