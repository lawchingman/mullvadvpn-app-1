package net.mullvad.mullvadvpn.test.arch

import com.lemonappdev.konsist.api.Konsist
import com.lemonappdev.konsist.api.architecture.KoArchitectureCreator.assertArchitecture
import com.lemonappdev.konsist.api.architecture.Layer
import org.junit.jupiter.api.Test

class ArchitectureTest {

    @Test
    fun `ensure model layer depends on nothing`() =
        Konsist.scopeFromProduction().assertArchitecture {
            val model = Layer("Model", "net.mullvad.mullvadvpn.lib.model..")

            model.dependsOnNothing()
        }
}
