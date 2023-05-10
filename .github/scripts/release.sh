#!/bin/env bash

version="${TAG_NAME}"
major="${version%%.*}" # see https://linuxjournal.com/article/8919 for an explanation of this bash magic

git tag "${version}"
git push origin "${version}"
push_worked=$?
if [ $push_worked -eq 0 ]; then
    echo "Created ${version} tag on remote."
    echo "Created \`${version}\` tag on remote." >> "$GITHUB_STEP_SUMMARY"
else
    echo "Failed to push ${version} tag to remote."
    echo "Failed to push \`${version}\` tag to remote." >> "$GITHUB_STEP_SUMMARY"
    exit 1
fi

git tag -d "${major}"
local_delete=$?
if [ $local_delete -eq 0 ]; then
    echo "Deleted local tag ${major}."
    echo "Deleted local tag \`${major}\`." >> "$GITHUB_STEP_SUMMARY"
else
    echo "No local tag ${major} to delete."
    echo "No local tag \`${major}\` to delete." >> "$GITHUB_STEP_SUMMARY"
fi
git tag "${major}"

git push -d origin "${major}"
remote_delete=$?
if [ $remote_delete -eq 0 ]; then
    echo "Deleted remote tag ${major}."
    echo "Deleted remote tag \`${major}\`." >> "$GITHUB_STEP_SUMMARY"
else
    echo "No remote tag ${major} to delete."
    echo "No remote tag \`${major}\` to delete." >> "$GITHUB_STEP_SUMMARY"
fi
git push origin "${major}"
push_worked=$?
if [ $push_worked -ne 0 ]; then
    echo "Failed to push ${major} tag to remote."
    echo "Failed to push \`${major}\` tag to remote." >> "$GITHUB_STEP_SUMMARY"
    exit 1
fi

if [ $remote_delete -eq 0 ]; then
    echo "Result: moved ${major} -> ${version} tag on remote."
    echo "Result: moved \`${major}\` -> \`${version}\` tag on remote." >> "$GITHUB_STEP_SUMMARY"
else
    echo "Result: created ${major} -> ${version} tag on remote."
    echo "Result: created \`${major}\` -> \`${version}\` tag on remote." >> "$GITHUB_STEP_SUMMARY"
fi
