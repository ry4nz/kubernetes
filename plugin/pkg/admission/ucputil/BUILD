load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = ["ucputil.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/api:go_default_library",
        "//pkg/apis/apps:go_default_library",
        "//pkg/apis/batch:go_default_library",
        "//pkg/apis/extensions:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/runtime:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = ["ucputil_test.go"],
    library = ":go_default_library",
    deps = [
        "//pkg/api:go_default_library",
        "//pkg/apis/apps:go_default_library",
        "//pkg/apis/batch:go_default_library",
        "//pkg/apis/extensions:go_default_library",
        "//vendor/github.com/stretchr/testify/assert:go_default_library",
        "//vendor/k8s.io/apimachinery/pkg/runtime:go_default_library",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
