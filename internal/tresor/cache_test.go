package tresor

import (
	"testing"
	"time"
)

var (
	size10mb int64 = 10 * 1024 * 1024
	size1mb  int64 = 1024 * 1024
)

func TestNewFileCache(t *testing.T) {
	fc := NewFileCache(size10mb) // 10 MB
	if fc == nil {
		t.Error("NewFileCache returned nil")
	}
	if fc.cache == nil {
		t.Error("cache map is nil")
	}
	if fc.Size() != 0 {
		t.Errorf("expected size 0, got %d", fc.Size())
	}
}

func TestGet_NotExists(t *testing.T) {
	fc := NewFileCache(size10mb)
	data, exists := fc.Get("nonexistent")
	if exists {
		t.Error("expected exists to be false")
	}
	if data != nil {
		t.Error("expected data to be nil")
	}
}

func TestGet_UpdatesAccessedTime(t *testing.T) {
	// Note: We can't directly test accessed time without exposing private fields.
	// This test just verifies Get() works consistently on the same entry.
	fc := NewFileCache(size10mb)
	testData := []byte("test content")
	fc.Set("test", testData)

	for i := 0; i < 3; i++ {
		data, exists := fc.Get("test")
		if !exists || string(data) != string(testData) {
			t.Error("Get() should return consistent data")
		}
	}
}

func TestGet_ReturnsCorrectData(t *testing.T) {
	fc := NewFileCache(size10mb)
	testData := []byte("hello world")
	fc.Set("myfile", testData)

	data, exists := fc.Get("myfile")
	if !exists {
		t.Error("expected exists to be true")
	}
	if string(data) != string(testData) {
		t.Errorf("expected %s, got %s", string(testData), string(data))
	}
}

func TestSet_SingleEntry(t *testing.T) {
	fc := NewFileCache(size10mb)
	testData := []byte("content")
	fc.Set("file1", testData)

	if fc.Size() != int64(len(testData)) {
		t.Errorf("expected size %d, got %d", int64(len(testData)), fc.Size())
	}

	data, exists := fc.Get("file1")
	if !exists || len(data) != len(testData) {
		t.Errorf("expected to retrieve %d bytes, got %d", len(testData), len(data))
	}
}

func TestSet_MultipleEntries(t *testing.T) {
	fc := NewFileCache(size10mb)
	data1 := []byte("content1")
	data2 := []byte("content2")
	data3 := []byte("content3")

	fc.Set("file1", data1)
	fc.Set("file2", data2)
	fc.Set("file3", data3)

	expectedSize := int64(len(data1) + len(data2) + len(data3))
	if fc.Size() != expectedSize {
		t.Errorf("expected size %d, got %d", expectedSize, fc.Size())
	}

	// Verify all entries exist
	if _, exists := fc.Get("file1"); !exists {
		t.Error("file1 not found")
	}
	if _, exists := fc.Get("file2"); !exists {
		t.Error("file2 not found")
	}
	if _, exists := fc.Get("file3"); !exists {
		t.Error("file3 not found")
	}
}

func TestSet_Overwrite(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file", []byte("old"))
	fc.Set("file", []byte("new content"))

	data, _ := fc.Get("file")
	if string(data) != "new content" {
		t.Errorf("expected 'new content', got %s", string(data))
	}

	// Size should only account for new content
	expectedSize := int64(len("new content"))
	if fc.Size() != expectedSize {
		t.Errorf("expected size %d after overwrite, got %d", expectedSize, fc.Size())
	}
}

func TestSet_InitializesBothTimes(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file", []byte("data"))

	data, exists := fc.Get("file")
	if !exists {
		t.Error("entry not found after Set()")
	}
	if data == nil {
		t.Error("data is nil")
	}

	// Entry should have been created and accessed around now
	if fc.Size() != 4 {
		t.Errorf("expected size 4, got %d", fc.Size())
	}
}

func TestDelete_ExistingEntry(t *testing.T) {
	fc := NewFileCache(size10mb)
	data := []byte("content")
	fc.Set("file", data)
	fc.Delete("file")

	if fc.Size() != 0 {
		t.Errorf("expected size 0 after delete, got %d", fc.Size())
	}
	if _, exists := fc.Get("file"); exists {
		t.Error("file still exists after delete")
	}
}

func TestDelete_NonexistentEntry(t *testing.T) {
	fc := NewFileCache(size10mb)
	// Should not panic
	fc.Delete("nonexistent")
	if fc.Size() != 0 {
		t.Errorf("expected size 0, got %d", fc.Size())
	}
}

func TestDelete_UpdatesSize(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file1", []byte("1111"))
	fc.Set("file2", []byte("2222"))
	fc.Set("file3", []byte("3333"))

	expectedSize := int64(12)
	if fc.Size() != expectedSize {
		t.Errorf("expected size %d, got %d", expectedSize, fc.Size())
	}

	fc.Delete("file2")
	// Size should be reduced by 4 bytes ("2222")
	expectedSize = int64(8)
	if fc.Size() != expectedSize {
		t.Errorf("expected size %d after delete, got %d", expectedSize, fc.Size())
	}

	// Verify file2 is gone
	if _, exists := fc.Get("file2"); exists {
		t.Error("file2 should not exist after delete")
	}
}

func TestClear(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file1", []byte("content1"))
	fc.Set("file2", []byte("content2"))

	if fc.Size() == 0 {
		t.Error("cache should not be empty before clear")
	}

	fc.Clear()

	if fc.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", fc.Size())
	}

	// Verify all entries are gone
	if _, exists := fc.Get("file1"); exists {
		t.Error("file1 should not exist after clear")
	}
	if _, exists := fc.Get("file2"); exists {
		t.Error("file2 should not exist after clear")
	}
}

func TestSize_Empty(t *testing.T) {
	fc := NewFileCache(size10mb)
	if fc.Size() != 0 {
		t.Errorf("expected size 0, got %d", fc.Size())
	}
}

func TestSize_Multiple(t *testing.T) {
	fc := NewFileCache(size10mb)

	sizes := []int{10, 20, 30}
	for i, size := range sizes {
		fc.Set("file0"+string(rune('0'+i)), make([]byte, size))
	}

	expectedSize := int64(60)
	if fc.Size() != expectedSize {
		t.Errorf("expected size %d, got %d", expectedSize, fc.Size())
	}
}

func TestEmptyData(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("empty", []byte{})

	data, exists := fc.Get("empty")
	if !exists {
		t.Error("expected to find empty data")
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
	if fc.Size() != 0 {
		t.Errorf("expected size 0 for empty data, got %d", fc.Size())
	}
}

func TestLargeData(t *testing.T) {
	fc := NewFileCache(size10mb)
	largeData := make([]byte, 1024*1024) // 1 MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	fc.Set("large", largeData)

	data, exists := fc.Get("large")
	if !exists {
		t.Error("expected to find large data")
	}
	if len(data) != len(largeData) {
		t.Errorf("expected %d bytes, got %d", len(largeData), len(data))
	}
	if fc.Size() != int64(len(largeData)) {
		t.Errorf("expected size %d, got %d", int64(len(largeData)), fc.Size())
	}
}

func TestManyEntries(t *testing.T) {
	fc := NewFileCache(size10mb)
	count := 100 // reduced for faster tests
	totalSize := int64(0)

	for i := 0; i < count; i++ {
		key := "file" + string(rune('0'+i%10))
		if i >= 10 {
			key = "file" + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10))
		}
		data := make([]byte, i+1)
		fc.Set(key, data)
		totalSize += int64(len(data))
	}

	if fc.Size() != totalSize {
		t.Errorf("expected size %d, got %d", totalSize, fc.Size())
	}
}

func TestGetAfterDelete(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file", []byte("content"))
	fc.Delete("file")

	data, exists := fc.Get("file")
	if exists {
		t.Error("expected exists to be false after delete")
	}
	if data != nil {
		t.Error("expected data to be nil after delete")
	}
}

func TestGetAfterClear(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file1", []byte("content1"))
	fc.Set("file2", []byte("content2"))
	fc.Clear()

	data, exists := fc.Get("file1")
	if exists {
		t.Error("expected exists to be false after clear")
	}
	if data != nil {
		t.Error("expected data to be nil after clear")
	}
}

func TestCaseSensitivity(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("File", []byte("uppercase"))
	fc.Set("file", []byte("lowercase"))

	// Keys should be treated as case-sensitive
	data1, exists1 := fc.Get("File")
	data2, exists2 := fc.Get("file")

	if !exists1 || string(data1) != "uppercase" {
		t.Error("uppercase key not found or wrong data")
	}
	if !exists2 || string(data2) != "lowercase" {
		t.Error("lowercase key not found or wrong data")
	}
	if fc.Size() != int64(len("uppercase")+len("lowercase")) {
		t.Errorf("expected size %d, got %d", int64(len("uppercase")+len("lowercase")), fc.Size())
	}

	// Different casing = different keys
	if _, exists := fc.Get("FILE"); exists {
		t.Error("FILE should not exist (different case)")
	}
}

func TestSequentialOperations(t *testing.T) {
	fc := NewFileCache(size10mb)

	// Set, Get, Delete, Get, Set sequence
	fc.Set("file", []byte("v1"))
	data, exists := fc.Get("file")
	if !exists || string(data) != "v1" {
		t.Error("first get failed")
	}

	fc.Delete("file")
	data, exists = fc.Get("file")
	if exists {
		t.Error("should not exist after delete")
	}

	fc.Set("file", []byte("v2"))
	data, exists = fc.Get("file")
	if !exists || string(data) != "v2" {
		t.Error("second set/get failed")
	}
}

func TestHas_Exists(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file", []byte("data"))

	if !fc.Has("file") {
		t.Error("Has() should return true for existing entry")
	}
}

func TestHas_NotExists(t *testing.T) {
	fc := NewFileCache(size10mb)
	if fc.Has("nonexistent") {
		t.Error("Has() should return false for non-existent entry")
	}
}

func TestHas_AfterDelete(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file", []byte("data"))
	fc.Delete("file")

	if fc.Has("file") {
		t.Error("Has() should return false after delete")
	}
}

func TestHas_AfterClear(t *testing.T) {
	fc := NewFileCache(size10mb)
	fc.Set("file1", []byte("data1"))
	fc.Set("file2", []byte("data2"))
	fc.Clear()

	if fc.Has("file1") || fc.Has("file2") {
		t.Error("Has() should return false after clear")
	}
}

func TestInactiveCache_Get(t *testing.T) {
	fc := NewFileCache(0) // inactive cache
	fc.Set("file", []byte("data"))

	data, exists := fc.Get("file")
	if exists {
		t.Error("Get() should return false for inactive cache")
	}
	if data != nil {
		t.Error("Get() should return nil for inactive cache")
	}
}

func TestInactiveCache_Has(t *testing.T) {
	fc := NewFileCache(0) // inactive cache
	fc.Set("file", []byte("data"))

	if fc.Has("file") {
		t.Error("Has() should return false for inactive cache")
	}
}

func TestInactiveCache_Set(t *testing.T) {
	fc := NewFileCache(0) // inactive cache
	fc.Set("file", []byte("data"))

	// Size should be 0 if cache is inactive
	if fc.Size() != 0 {
		t.Errorf("expected size 0 for inactive cache, got %d", fc.Size())
	}
}

func TestInactiveCache_NegativeMaxSize(t *testing.T) {
	fc := NewFileCache(-100) // negative maxSize means inactive
	fc.Set("file", []byte("data"))

	if fc.Has("file") {
		t.Error("Has() should return false for cache with negative maxSize")
	}
	if fc.Size() != 0 {
		t.Errorf("expected size 0 for inactive cache, got %d", fc.Size())
	}
}

func TestEviction_MaxSize(t *testing.T) {
	fc := NewFileCache(10)           // 10 bytes max
	fc.Set("file1", []byte("12345")) // 5 bytes
	fc.Set("file2", []byte("67890")) // 5 bytes - should fit
	// Total: 10 bytes

	if fc.Size() != 10 {
		t.Errorf("expected size 10, got %d", fc.Size())
	}

	fc.Set("file3", []byte("abc")) // 3 bytes - should trigger eviction
	// Should evict least recently accessed (file1)
	if fc.Has("file1") {
		t.Error("file1 should be evicted")
	}
	if !fc.Has("file2") {
		t.Error("file2 should still exist")
	}
	if !fc.Has("file3") {
		t.Error("file3 should exist")
	}
}

func TestEviction_LeastRecentlyAccessed(t *testing.T) {
	fc := NewFileCache(20)           // 20 bytes max
	fc.Set("file1", []byte("12345")) // 5 bytes
	time.Sleep(1 * time.Millisecond)
	fc.Set("file2", []byte("67890")) // 5 bytes
	time.Sleep(1 * time.Millisecond)
	fc.Set("file3", []byte("abcde")) // 5 bytes
	time.Sleep(1 * time.Millisecond)
	// Total: 15 bytes

	// Access file1 and file2 to update their accessed time
	fc.Get("file1")
	time.Sleep(1 * time.Millisecond)
	fc.Get("file2")
	time.Sleep(1 * time.Millisecond)

	// Add file4 (5 bytes) - total would be 20
	fc.Set("file4", []byte("fghij")) // 5 bytes
	time.Sleep(1 * time.Millisecond)

	if fc.Size() != 20 {
		t.Errorf("expected size 20, got %d", fc.Size())
	}

	// Now add file5 (5 bytes) - should evict file3 (least recently accessed)
	fc.Set("file5", []byte("klmno"))

	if !fc.Has("file1") {
		t.Error("file1 should still exist")
	}
	if !fc.Has("file2") {
		t.Error("file2 should still exist")
	}
	if fc.Has("file3") {
		t.Error("file3 should be evicted (least recently accessed)")
	}
	if !fc.Has("file4") {
		t.Error("file4 should still exist")
	}
	if !fc.Has("file5") {
		t.Error("file5 should exist")
	}
}
