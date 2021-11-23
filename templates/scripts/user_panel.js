$(document).ready(function () {
    var counter = 1;
    $(function () {
        $("#add-product").click(function (event) {
            console.log("data");
            var new_product_data = { tag_id: $('#product-id').val() }
            $.getJSON('/get_product_for_tag', new_product_data,
                    function (response) {
                    var data = JSON.parse(response);

                    var newRow = $("<tr data-product-id=data.tag_id>");
                    var cols = "";
                    cols += '<td class="col-1" style="vertical-align: middle;"><img src=https://picsum.photos/200 class="img me-3" width="100" height="100" alt="..."></td>'
                    cols += '<td class="col-24"><h5 style="color: var(--secondary); font-weight: bold;">' + data.product.name + '</h5>'
                    if ('short_desc' in data.product) {
                        cols += '<p class="mb-0">' + data.product.short_desc + '</p>'
                    }
                    if ('purchase_date_str' in data) {
                        cols += '<p class="mb-0">Purchase date: ' + data.purchase_date_str + '</p>'
                    }
                    if (!('product_short_desc' in data) && !('purchase_date_str' in data)) {
                        cols += '<p class="mb-0">&nbsp;</p>'
                    }
                    newRow.append(cols);
                    $("table.product-list").append(newRow);
                    counter++;

                    newRow = $("<tr data-product-id=data.tag_id>");
                    cols = '<td colspan="2"><div class="d-flex flex-row-reverse"><div class="btn-group" role="group" aria-label="Basic example"><button type="submit" class="btn product-btn-del btn-primary-outline shadow-none" style="margin-right: -1px;">Remove</button><button type="submit" class="btn product-btn-edit btn-primary-outline shadow-none" style="margin-right: -1px;">Edit</button><button type="submit" class="btn product-btn-show btn-primary-outline shadow-none" style="margin-right: -1px;">Preview</button><img src="{{url_for('static', filename='bowtie.png')}}" style="position: absolute; z-index:10; height: 20px; right: 20px; top: -12px;">';
                    if (data.visible) {
                        cols += '<button type="submit" class="btn product-btn-stop btn-primary-outline shadow-none">Stop</button></div></div></td>';
                    } else {
                        cols += '<button type="submit" class="btn product-btn-start btn-primary-outline shadow-none">Start</button></div></div></td>';
                    }
                    newRow.append(cols);
                    $("table.product-list").append(newRow);
                    counter++;

                });
            return false;
        });
    });

    $("table.product-list").on("click", ".product-btn-show", function (event) {
        var product_id = $(this).closest("tr").attr("data-product-id")
        window.location.href = "/gift?tag_id=" + product_id;
    });

    $("table.product-list").on("click", ".product-btn-start", function (event) {
        var product_id = $(this).closest("tr").attr("data-product-id")
        $.getJSON('/switch_tag_visibility', { "tag_id": product_id, "target_visibility": true },
            function (response) { console.log(response) });
        $(this).text('Stop')
            .removeClass("btn-success")
            .addClass("btn-danger")
            .removeClass("product-btn-start")
            .addClass("product-btn-stop")
            .show();
    });

    $("table.product-list").on("click", ".product-btn-stop", function (event) {
        var product_id = $(this).closest("tr").attr("data-product-id")
        $.getJSON('/switch_tag_visibility', { "tag_id": product_id, "target_visibility": false },
            function (response) { console.log(response) });

        $(this).text('Start')
            .removeClass("btn-danger")
            .addClass("btn-success")
            .removeClass('product-btn-stop')
            .addClass("product-btn-start")
            .show();
    });
    $("table.product-list").on("click", ".product-btn-del", function (event) {
        var product_id = $(this).closest("tr").attr("data-product-id");
        var index = $(this).closest("tr").index();
        var prev_index = index - 1
        $("table.product-list tr:eq(" + index + ")").remove();
        $("table.product-list tr:eq(" + prev_index + ")").remove();
        $.getJSON('/delete_tag_for_user', { "tag_id": product_id },
            function (response) { console.log(response) });
    });
    $("table.product-list").on("click", ".product-btn-edit", function (event) {
        var product_id = $(this).closest("tr").attr("data-product-id")
        window.location.href = "/upload?tag_id=" + product_id;
    });
});