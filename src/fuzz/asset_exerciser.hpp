#pragma once

#include <fastgltf/core.hpp>
#include <fastgltf/tools.hpp>

namespace fastgltf_fuzz {

/**
 * Executes bounded deep accessor traversal on a parsed fastgltf::Asset.
 *
 * Implements:
 * 1. ElementType-compatible accessor dispatch.
 * 2. Metamorphic oracle comparing getAccessorElement, iterateAccessor,
 *    iterateAccessorWithIndex, and copyFromAccessor.
 * 3. Execution against both DefaultBufferDataAdapter and GuardedBufferDataAdapter.
 * 4. Telemetry logging and extent verification.
 */
void exerciseAsset(const fastgltf::Asset& asset);

} // namespace fastgltf_fuzz
