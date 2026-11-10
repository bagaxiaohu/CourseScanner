rule Course_Demo_Logical {
    strings:
        $family = "COURSE_DEMO_FAMILY_2026"
        $feature = "COURSE_DEMO_FEATURE_ALPHA"
    condition:
        all of them
}
